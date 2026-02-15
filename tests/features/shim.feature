@shim
Feature: POOL Shim Compatibility
  The libpool_shim.so LD_PRELOAD interceptor must support
  server-side accept, non-blocking I/O, event loops, IPv6,
  vectored I/O, high FD counts, and module reloads.

  Background:
    Given the POOL kernel module is loaded
    And a POOL listener is started on port 9253

  # 3.1 CRITICAL — accept() is a passthrough
  @critical
  Scenario: Server application accepts incoming POOL connections via shim
    Given a server application is running with libpool_shim.so loaded
    And the server calls listen() and accept() on port 8080
    When a POOL client connects to the server
    Then the server's accept() returns a valid file descriptor
    And the server can send and receive data over the POOL session

  Scenario: Server accepts both TCP and POOL connections
    Given a server application is running with libpool_shim.so loaded
    And the server calls listen() and accept() on port 8080
    And POOL_SHIM_FALLBACK is set to 1
    When a TCP client and a POOL client connect simultaneously
    Then the server accepts both connections
    And each connection uses its respective transport

  # 3.2 CRITICAL — Non-blocking I/O broken
  @critical
  Scenario: Non-blocking recv returns EAGAIN when no data is pending
    Given a POOL session is established via the shim
    And the socket is set to O_NONBLOCK via fcntl
    When I call recv() with no data pending
    Then recv() returns -1 with errno EAGAIN
    And the call completes within 1 millisecond

  Scenario: Non-blocking send succeeds when session is established
    Given a POOL session is established via the shim
    And the socket is set to O_NONBLOCK via fcntl
    When I call send() with 100 bytes of data
    Then send() returns 100
    And the data is delivered to the peer

  # 3.3 CRITICAL — epoll/poll/select not intercepted
  @critical
  Scenario: poll() detects readable POOL socket
    Given a POOL session is established via the shim
    When the peer sends 100 bytes of data
    And I call poll() with POLLIN on the POOL socket with a 5 second timeout
    Then poll() returns within 1 second
    And the POLLIN flag is set
    And recv() returns the 100 bytes

  Scenario: poll() detects writable POOL socket
    Given a POOL session is established via the shim
    When I call poll() with POLLOUT on the POOL socket
    Then poll() returns immediately
    And the POLLOUT flag is set

  Scenario: select() works with POOL sockets
    Given a POOL session is established via the shim
    When the peer sends data
    And I call select() with the POOL socket in the read set
    Then select() returns with the socket marked readable

  # 3.4 HIGH — IPv6 not supported
  @high
  Scenario: IPv4-mapped IPv6 address routes through POOL
    Given libpool_shim.so is loaded
    When I connect to the IPv4-mapped IPv6 address "::ffff:127.0.0.1" port 9253
    Then the connection is established via POOL
    And data can be sent and received

  Scenario: Pure IPv6 address falls back to TCP
    Given libpool_shim.so is loaded
    And POOL_SHIM_FALLBACK is set to 1
    When I connect to a pure IPv6 address "::1" port 8080
    Then the connection falls back to TCP
    And a log message indicates IPv6 fallback

  # 3.5 HIGH — sendmsg/recvmsg not intercepted
  @high
  Scenario: sendmsg with vectored I/O transmits over POOL
    Given a POOL session is established via the shim
    When I call sendmsg() with a 3-element iovec containing "Hello", ", ", and "POOL"
    Then all data is transmitted over POOL
    And the peer receives "Hello, POOL"

  Scenario: recvmsg with vectored I/O receives from POOL
    Given a POOL session is established via the shim
    And the peer sends "Hello, POOL"
    When I call recvmsg() with a 2-element iovec
    Then the data is scattered across the iovec buffers
    And the total received matches "Hello, POOL"

  Scenario: writev transmits over POOL
    Given a POOL session is established via the shim
    When I call writev() with 2 iovec segments
    Then all data is transmitted over POOL

  Scenario: readv receives from POOL
    Given a POOL session is established via the shim
    And the peer sends data
    When I call readv() with 2 iovec segments
    Then data is scattered across the segments

  # 3.6 HIGH — FD limit too low
  @high
  Scenario: File descriptors above 1024 are managed by the shim
    Given libpool_shim.so is loaded
    When I open 2000 sockets via the shim
    Then socket number 1500 is correctly managed by POOL
    And connect() on FD 1500 routes through POOL

  # 3.7 MEDIUM — Stale session after module reload
  @medium
  Scenario: Shim handles module reload gracefully
    Given a POOL session is established via the shim
    When the POOL kernel module is reloaded
    And I attempt to send data on the old session
    Then the send returns a graceful error or triggers automatic reconnection
    And no crash or undefined behavior occurs
