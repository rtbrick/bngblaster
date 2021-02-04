/*
Ethernet II, Src: 02:00:00:00:00:01 (02:00:00:00:00:01), Dst: 7a:52:4a:c0:00:01 (7a:52:4a:c0:00:01)
802.1Q Virtual LAN, PRI: 0, DEI: 0, ID: 1
802.1Q Virtual LAN, PRI: 0, DEI: 0, ID: 1
PPP-over-Ethernet Session
    0001 .... = Version: 1
    .... 0001 = Type: 1
    Code: Session Data (0x00)
    Session ID: 0x0001
    Payload Length: 24
Point-to-Point Protocol
    Protocol: Internet Protocol Control Protocol (0x8021)
PPP IP Control Protocol
    Code: Configuration Request (1)
    Identifier: 2 (0x02)
    Length: 22
    Options: (18 bytes), IP Address, Primary DNS Server IP Address, Secondary DNS Server IP Address
        IP Address
            Type: IP Address (3)
            Length: 6
            IP Address: 10.137.0.0
        Primary DNS Server IP Address
            Type: Primary DNS Server IP Address (129)
            Length: 6
            Primary DNS Address: 100.0.0.3
        Secondary DNS Server IP Address
            Type: Secondary DNS Server IP Address (131)
            Length: 6
            Secondary DNS Address: 100.0.0.4
*/
uint8_t pppoe_ipcp_conf_request[] = {
  0x7a, 0x52, 0x4a, 0xc0, 0x00, 0x01, 0x02, 0x00,
  0x00, 0x00, 0x00, 0x01, 0x81, 0x00, 0x00, 0x01,
  0x81, 0x00, 0x00, 0x01, 0x88, 0x64, 0x11, 0x00,
  0x00, 0x01, 0x00, 0x18, 0x80, 0x21, 0x01, 0x02,
  0x00, 0x16, 0x03, 0x06, 0x0a, 0x89, 0x00, 0x00,
  0x81, 0x06, 0x64, 0x00, 0x00, 0x03, 0x83, 0x06,
  0x64, 0x00, 0x00, 0x04
};
