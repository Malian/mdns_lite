# SPDX-FileCopyrightText: 2021 Frank Hunleth
# SPDX-FileCopyrightText: 2021 Mat Trudel
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule MdnsLite.TableTest do
  use ExUnit.Case

  import MdnsLite.DNS

  alias MdnsLite.Options
  alias MdnsLite.Table

  doctest MdnsLite.Table

  # The NSEC record of nerves-21a5.local that says it has an A record and nothing else: the next domain is the
  # name itself (RFC 6762 6.1), then window 0 with one byte of bitmap where bit 1 is A.
  @nsec_a_only dns_rr(
                 domain: ~c"nerves-21a5.local",
                 type: 47,
                 class: :in,
                 ttl: 120,
                 func: true,
                 data: <<11, "nerves-21a5", 5, "local", 0, 0, 1, 0x40>>
               )

  @a_record dns_rr(
              domain: ~c"nerves-21a5.local",
              type: :a,
              class: :in,
              ttl: 120,
              data: {192, 168, 9, 57}
            )

  @nsec_alias_a_only dns_rr(
                       domain: ~c"nerves.local",
                       type: 47,
                       class: :in,
                       ttl: 120,
                       func: true,
                       data: <<6, "nerves", 5, "local", 0, 0, 1, 0x40>>
                     )

  defp test_config() do
    %Options{}
    |> Options.add_hosts(["nerves-21a5", "nerves"])
    |> Options.add_services([
      %{
        id: :http_service,
        txt_payload: ["key=value"],
        port: 80,
        priority: 0,
        protocol: "http",
        transport: "tcp",
        type: "_http._tcp",
        weight: 0
      },
      %{
        id: :ssh_service,
        txt_payload: [""],
        port: 22,
        priority: 0,
        protocol: "ssh",
        transport: "tcp",
        type: "_ssh._tcp",
        weight: 0
      }
    ])
  end

  defp do_query(
         query,
         config \\ test_config(),
         if_info \\ %MdnsLite.IfInfo{ipv4_address: {192, 168, 9, 57}}
       ) do
    table = Table.Builder.from_options(config)
    answer_rr = Table.query(table, query, if_info)
    additional_rr = Table.additional_records(table, answer_rr, if_info)
    %{answer: answer_rr, additional: additional_rr}
  end

  test "responds to an A request" do
    query = dns_query(domain: ~c"nerves-21a5.local", type: :a, class: :in)

    result = %{
      answer: [
        dns_rr(
          domain: ~c"nerves-21a5.local",
          type: :a,
          class: :in,
          ttl: 120,
          data: {192, 168, 9, 57}
        )
      ],
      additional: [@nsec_a_only]
    }

    assert do_query(query) == result
  end

  test "responds to an A request for the alias" do
    query = dns_query(domain: ~c"nerves.local", type: :a, class: :in)

    result = %{
      answer: [
        dns_rr(domain: ~c"nerves.local", type: :a, class: :in, ttl: 120, data: {192, 168, 9, 57})
      ],
      additional: [@nsec_alias_a_only]
    }

    assert do_query(query) == result
  end

  test "responds to a unicast A request" do
    query = dns_query(domain: ~c"nerves-21a5.local", type: :a, class: :in, unicast_response: true)

    result = %{
      answer: [
        dns_rr(
          domain: ~c"nerves-21a5.local",
          type: :a,
          class: :in,
          ttl: 120,
          data: {192, 168, 9, 57}
        )
      ],
      additional: [@nsec_a_only]
    }

    assert do_query(query) == result
  end

  test "ignores A request for someone else" do
    query =
      dns_query(domain: ~c"someone-else.local", type: :a, class: :in, unicast_response: true)

    assert do_query(query) == %{answer: [], additional: []}
  end

  describe "negative responses (RFC 6762 6.1 and 6.2)" do
    test "answers an AAAA request on an IPv4-only interface with an NSEC record" do
      query = dns_query(domain: ~c"nerves-21a5.local", type: :aaaa, class: :in)

      assert do_query(query) == %{answer: [@nsec_a_only], additional: []}
    end

    test "adds the NSEC record for the missing AAAA to an A answer" do
      query = dns_query(domain: ~c"nerves-21a5.local", type: :a, class: :in)

      assert do_query(query) == %{answer: [@a_record], additional: [@nsec_a_only]}
    end

    test "adds the AAAA records to an A answer on an interface that has them" do
      query = dns_query(domain: ~c"nerves-21a5.local", type: :a, class: :in)
      ipv6 = {0xFE80, 0, 0, 0, 0xBA27, 0xEBFF, 0xFE01, 0x0203}
      if_info = %MdnsLite.IfInfo{ipv4_address: {192, 168, 9, 57}, ipv6_addresses: [ipv6]}

      assert do_query(query, test_config(), if_info) == %{
               answer: [@a_record],
               additional: [
                 dns_rr(
                   domain: ~c"nerves-21a5.local",
                   type: :aaaa,
                   class: :in,
                   ttl: 120,
                   data: ipv6
                 )
               ]
             }
    end

    test "says nothing about a name that is someone else's" do
      query = dns_query(domain: ~c"someone-else.local", type: :aaaa, class: :in)

      assert do_query(query) == %{answer: [], additional: []}
    end

    test "the NSEC record is encoded as type 47 and decodes back to itself" do
      packet = dns_rec(header: dns_header(id: 0, qr: true, aa: true), anlist: [@nsec_a_only])

      assert {:ok, decoded} = packet |> MdnsLite.DNS.encode() |> MdnsLite.DNS.decode()
      assert [dns_rr(type: 47, func: true, data: data)] = dns_rec(decoded, :anlist)
      assert data == dns_rr(@nsec_a_only, :data)
    end
  end

  test "responds to a PTR request with a reverse lookup domain" do
    query = dns_query(domain: ~c"57.9.168.192.in-addr.arpa.", type: :ptr, class: :in)

    result = %{
      answer: [
        dns_rr(
          domain: ~c"57.9.168.192.in-addr.arpa.",
          type: :ptr,
          class: :in,
          ttl: 120,
          data: ~c"nerves-21a5.local"
        )
      ],
      additional: []
    }

    assert do_query(query) == result
  end

  test "responds to a PTR request with a specific domain" do
    test_domain = ~c"_http._tcp.local"
    query = dns_query(domain: test_domain, type: :ptr, class: :in)

    result = %{
      answer: [
        dns_rr(
          domain: test_domain,
          type: :ptr,
          class: :in,
          ttl: 120,
          data: ~c"nerves-21a5._http._tcp.local"
        )
      ],
      additional: [
        dns_rr(
          domain: ~c"nerves-21a5._http._tcp.local",
          type: :srv,
          class: :in,
          ttl: 120,
          data: {0, 0, 80, ~c"nerves-21a5.local."}
        ),
        dns_rr(
          domain: ~c"nerves-21a5._http._tcp.local",
          type: :txt,
          class: :in,
          ttl: 120,
          data: ["key=value"]
        ),
        dns_rr(
          domain: ~c"nerves-21a5.local",
          type: :a,
          class: :in,
          ttl: 120,
          data: {192, 168, 9, 57}
        ),
        @nsec_a_only
      ]
    }

    assert do_query(query) == result
  end

  test "responds to a PTR request with a specific domain using host-level instance name" do
    test_domain = ~c"_http._tcp.local"
    query = dns_query(domain: test_domain, type: :ptr, class: :in)

    result = %{
      answer: [
        dns_rr(
          domain: test_domain,
          type: :ptr,
          class: :in,
          ttl: 120,
          data: ~c"myidentifier._http._tcp.local"
        )
      ],
      additional: [
        dns_rr(
          domain: ~c"myidentifier._http._tcp.local",
          type: :srv,
          class: :in,
          ttl: 120,
          data: {0, 0, 80, ~c"nerves-21a5.local."}
        ),
        dns_rr(
          domain: ~c"myidentifier._http._tcp.local",
          type: :txt,
          class: :in,
          ttl: 120,
          data: ["key=value"]
        ),
        dns_rr(
          domain: ~c"nerves-21a5.local",
          type: :a,
          class: :in,
          ttl: 120,
          data: {192, 168, 9, 57}
        ),
        @nsec_a_only
      ]
    }

    config =
      %Options{}
      |> Options.add_hosts(["nerves-21a5", "nerves"])
      |> Options.set_instance_name("myidentifier")
      |> Options.add_service(%{
        id: :http_service,
        txt_payload: ["key=value"],
        port: 80,
        priority: 0,
        protocol: "http",
        transport: "tcp",
        type: "_http._tcp",
        weight: 0
      })

    assert do_query(query, config) == result
  end

  test "responds to a PTR request with a specific domain using service-level instance name" do
    test_domain = ~c"_http._tcp.local"
    query = dns_query(domain: test_domain, type: :ptr, class: :in)

    result = %{
      answer: [
        dns_rr(
          domain: test_domain,
          type: :ptr,
          class: :in,
          ttl: 120,
          data: ~c"myidentifier._http._tcp.local"
        )
      ],
      additional: [
        dns_rr(
          domain: ~c"myidentifier._http._tcp.local",
          type: :srv,
          class: :in,
          ttl: 120,
          data: {0, 0, 80, ~c"nerves-21a5.local."}
        ),
        dns_rr(
          domain: ~c"myidentifier._http._tcp.local",
          type: :txt,
          class: :in,
          ttl: 120,
          data: ["key=value"]
        ),
        dns_rr(
          domain: ~c"nerves-21a5.local",
          type: :a,
          class: :in,
          ttl: 120,
          data: {192, 168, 9, 57}
        ),
        @nsec_a_only
      ]
    }

    config =
      %Options{}
      |> Options.add_hosts(["nerves-21a5", "nerves"])
      |> Options.add_service(%{
        id: :http_service,
        instance_name: "myidentifier",
        txt_payload: ["key=value"],
        port: 80,
        priority: 0,
        protocol: "http",
        transport: "tcp",
        type: "_http._tcp",
        weight: 0
      })

    assert do_query(query, config) == result
  end

  test "responds to a PTR request with domain \'_services._dns-sd._udp.local\'" do
    test_domain = ~c"_services._dns-sd._udp.local"
    query = dns_query(domain: test_domain, type: :ptr, class: :in)

    result = %{
      answer: [
        dns_rr(
          domain: ~c"_services._dns-sd._udp.local",
          type: :ptr,
          class: :in,
          ttl: 120,
          data: ~c"_http._tcp.local"
        ),
        dns_rr(
          domain: ~c"_services._dns-sd._udp.local",
          type: :ptr,
          class: :in,
          ttl: 120,
          data: ~c"_ssh._tcp.local"
        )
      ],
      additional: []
    }

    assert do_query(query) == result
  end

  test "responds to an SRV request for a known service" do
    known_service = "nerves-21a5._http._tcp.local"
    query = dns_query(domain: to_charlist(known_service), type: :srv, class: :in)

    result = %{
      answer: [
        dns_rr(
          domain: ~c"nerves-21a5._http._tcp.local",
          type: :srv,
          class: :in,
          ttl: 120,
          data: {0, 0, 80, ~c"nerves-21a5.local."}
        )
      ],
      additional: [
        {:dns_rr, ~c"nerves-21a5.local", :a, :in, 0, 120, {192, 168, 9, 57}, :undefined, [],
         false},
        @nsec_a_only
      ]
    }

    assert do_query(query) == result
  end

  test "responds to an SRV request for a known service with host-level instance name" do
    known_service = "myidentifier._http._tcp.local"
    query = dns_query(domain: to_charlist(known_service), type: :srv, class: :in)

    result = %{
      answer: [
        dns_rr(
          domain: ~c"myidentifier._http._tcp.local",
          type: :srv,
          class: :in,
          ttl: 120,
          data: {0, 0, 80, ~c"nerves-21a5.local."}
        )
      ],
      additional: [
        {:dns_rr, ~c"nerves-21a5.local", :a, :in, 0, 120, {192, 168, 9, 57}, :undefined, [],
         false},
        @nsec_a_only
      ]
    }

    config =
      %Options{}
      |> Options.add_hosts(["nerves-21a5", "nerves"])
      |> Options.set_instance_name("myidentifier")
      |> Options.add_service(%{
        id: :http_service,
        txt_payload: ["key=value"],
        port: 80,
        priority: 0,
        protocol: "http",
        transport: "tcp",
        type: "_http._tcp",
        weight: 0
      })

    assert do_query(query, config) == result
  end

  test "responds to an SRV request for a known service with service-level instance name" do
    known_service = "myidentifier._http._tcp.local"
    query = dns_query(domain: to_charlist(known_service), type: :srv, class: :in)

    result = %{
      answer: [
        dns_rr(
          domain: ~c"myidentifier._http._tcp.local",
          type: :srv,
          class: :in,
          ttl: 120,
          data: {0, 0, 80, ~c"nerves-21a5.local."}
        )
      ],
      additional: [
        {:dns_rr, ~c"nerves-21a5.local", :a, :in, 0, 120, {192, 168, 9, 57}, :undefined, [],
         false},
        @nsec_a_only
      ]
    }

    config =
      %Options{}
      |> Options.add_hosts(["nerves-21a5", "nerves"])
      |> Options.add_service(%{
        id: :http_service,
        instance_name: "myidentifier",
        txt_payload: ["key=value"],
        port: 80,
        priority: 0,
        protocol: "http",
        transport: "tcp",
        type: "_http._tcp",
        weight: 0
      })

    assert do_query(query, config) == result
  end

  test "ignore SRV request without the instance name" do
    service_only = "_http._tcp.local"
    query = dns_query(domain: to_charlist(service_only), type: :srv, class: :in)

    assert do_query(query) == %{answer: [], additional: []}
  end
end
