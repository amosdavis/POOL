@ipv6
Feature: Full Native IPv6 Support
  The POOL protocol stack must support IPv6 addresses natively across
  kernel module, bridge, shim, and CLI tools. IPv4 addresses are stored
  internally as IPv4-mapped IPv6 (::ffff:x.x.x.x). The kernel listener
  uses AF_INET6 dual-stack to accept both IPv4 and IPv6 connections.

  # ---- Kernel Module ----

  Background:
    Given the POOL kernel module is loaded
    And a POOL listener is started on port 9253

  @kernel @critical
  Scenario: Dual-stack listener accepts IPv4 connections
    When a client connects to "127.0.0.1" port 9253
    Then the session is established successfully
    And the session peer address is "::ffff:127.0.0.1"
    And the session address family is AF_INET

  @kernel @critical
  Scenario: Dual-stack listener accepts IPv6 connections
    When a client connects to "::1" port 9253
    Then the session is established successfully
    And the session peer address is "::1"
    And the session address family is AF_INET6

  @kernel @high
  Scenario: IPv6 connect request via ioctl
    When a POOL_IOC_CONNECT is issued with address "fd00::1" and family AF_INET6
    Then the connect request uses the full 128-bit address
    And the addr_family field is set to AF_INET6

  @kernel @high
  Scenario: IPv4-mapped address stored correctly
    When a client connects to "10.0.0.1" port 9253
    Then the internal peer_addr contains the IPv4-mapped bytes for "10.0.0.1"
    And pool_addr_is_v4mapped returns true

  @kernel @high
  Scenario: IPv6 crypto puzzle uses full 16-byte address
    When a client connects to "::1" port 9253
    And a proof-of-work puzzle is generated
    Then the puzzle input contains the full 16-byte client address
    And the puzzle input buffer is 28 bytes

  @kernel @medium
  Scenario: Session info reports IPv6 addresses via ioctl
    Given a POOL session is established to "::1" port 9253
    When POOL_IOC_SESSIONS is called
    Then the session info contains peer_addr with 16 bytes
    And the session info addr_family is AF_INET6
    And the peer_port is 9253

  @kernel @medium
  Scenario: IPv6 address logged with correct format
    When a client connects to "::1" port 9253
    Then kernel log contains an IPv6-formatted address
    And no "%pI4" format specifier is used for IPv6 peers

  # ---- Bridge ----

  @bridge @high
  Scenario: Bridge TCP listener accepts IPv6 connections
    Given the POOL bridge is started in tcp-to-pool mode on port 8080
    When an IPv6 TCP client connects to "[::1]:8080"
    Then the bridge accepts the connection
    And the bridge forwards traffic over POOL

  @bridge @high
  Scenario: Bridge connects to IPv6 TCP destination
    Given the POOL bridge is started in pool-to-tcp mode
    And the TCP destination is "[::1]:8080"
    When a POOL session delivers data
    Then the bridge connects to the IPv6 TCP destination
    And data is forwarded correctly

  @bridge @high
  Scenario: Bridge CLI parses IPv6 literal with brackets
    When the bridge is started with arguments "--tcp-to-pool [::1]:8080 9253"
    Then the bridge resolves "[::1]" as an IPv6 address
    And the port is parsed as 8080

  @bridge @medium
  Scenario: Bridge CLI resolves hostname to IPv6
    When the bridge is started with destination "localhost" port 8080
    Then getaddrinfo resolves the hostname
    And the bridge accepts both IPv4 and IPv6 results

  # ---- Shim ----

  @shim @critical
  Scenario: Shim intercepts native IPv6 connect
    Given the POOL shim library is loaded
    When an application calls connect with AF_INET6 to "fd00::1" port 443
    Then the shim populates peer_addr with the full 128-bit address
    And the shim sets addr_family to AF_INET6
    And the connection is routed through POOL

  @shim @critical
  Scenario: Shim handles IPv4-mapped IPv6 in connect
    Given the POOL shim library is loaded
    When an application calls connect with AF_INET6 to "::ffff:10.0.0.1" port 443
    Then the shim detects the IPv4-mapped address
    And the addr_family is set to AF_INET
    And the connection is routed through POOL

  @shim @high
  Scenario: Shim accept returns IPv6 sockaddr for IPv6 peers
    Given the POOL shim library is loaded
    And a shim-intercepted listener is active on port 443
    When an IPv6 POOL session is accepted
    Then the returned sockaddr is sockaddr_in6
    And the sin6_addr contains the peer's IPv6 address
    And the sin6_port contains the peer's port

  @shim @high
  Scenario: Shim getpeername returns correct family for IPv6
    Given the POOL shim library is loaded
    And a POOL session is established to "fd00::1" port 443
    When the application calls getpeername
    Then the returned sockaddr is sockaddr_in6
    And the sin6_family is AF_INET6

  @shim @high
  Scenario: Shim getpeername returns IPv4 for mapped addresses
    Given the POOL shim library is loaded
    And a POOL session is established to "::ffff:192.168.1.1" port 443
    When the application calls getpeername
    Then the returned sockaddr is sockaddr_in
    And the sin_family is AF_INET
    And the sin_addr is "192.168.1.1"

  @shim @medium
  Scenario: Shim bind tracks IPv6 addresses
    Given the POOL shim library is loaded
    When the application binds to "[::]:443"
    Then the shim records the bind address as IPv6
    And the bind_family is AF_INET6

  # ---- CLI Tools ----

  @cli @high
  Scenario: poolctl connect accepts IPv6 address
    Given the POOL kernel module is loaded
    When "poolctl connect ::1 9253" is executed
    Then the connect request uses AF_INET6
    And the peer_addr is set to "::1"

  @cli @high
  Scenario: poolctl connect accepts hostname
    Given the POOL kernel module is loaded
    When "poolctl connect localhost 9253" is executed
    Then getaddrinfo resolves the hostname
    And the connect request uses the resolved address

  @cli @high
  Scenario: poolctl sessions displays IPv6 addresses
    Given a POOL session is established to "::1" port 9253
    When "poolctl sessions" is executed
    Then the output shows the peer address in IPv6 notation
    And the column width accommodates IPv6 addresses

  @cli @high
  Scenario: pool_test client accepts IPv6 address
    When "pool_test client ::1 9253 1" is executed
    Then the connect request uses AF_INET6
    And the test proceeds with the IPv6 peer

  @cli @high
  Scenario: pool_vault connect accepts IPv6 address
    When "pool_vault push ::1 /tmp/testfile /remote/path" is executed
    Then the connect request uses AF_INET6
    And the vault establishes a POOL session to "::1"

  @cli @high
  Scenario: pool_relay enroll accepts IPv6 address
    Given the relay daemon is running
    When "pool_relay enroll ::1" is executed
    Then the enroll request uses AF_INET6
    And a relay peer entry is created with the IPv6 address

  @cli @medium
  Scenario: pool_migrate test accepts IPv6 address
    When "pool_migrate test ::1 9253" is executed
    Then the test connects using AF_INET6
    And the connectivity result is displayed

  # ---- Address Helper Functions ----

  @helpers @medium
  Scenario: pool_ipv4_to_mapped converts correctly
    When IPv4 address 0x0A000001 is converted to mapped
    Then the result is the 16-byte sequence for "::ffff:10.0.0.1"

  @helpers @medium
  Scenario: pool_mapped_to_ipv4 extracts correctly
    When the mapped address for "::ffff:192.168.1.1" is converted back
    Then the result is 0xC0A80101

  @helpers @medium
  Scenario: pool_addr_is_v4mapped detects mapped addresses
    Given an address "::ffff:10.0.0.1"
    Then pool_addr_is_v4mapped returns true

  @helpers @medium
  Scenario: pool_addr_is_v4mapped rejects native IPv6
    Given an address "fd00::1"
    Then pool_addr_is_v4mapped returns false
