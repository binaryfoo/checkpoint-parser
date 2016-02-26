package io.github.binaryfoo.firewall.cp

class ExtractorSpec extends FwSpec {

  "Addresses" should "be extracted" in {
    val addresses = Extractor.extractAddressLines(testFile("w_control.pf"))
    addresses shouldBe List("ADDR_net(testfw-net-if0, 192.168.1.0, 255.255.255.0)", "ADDR_net(testfw-net-if1, 192.168.2.0, 255.255.255.0)", "ADDR_net(testfw-net-if2, 192.168.3.0, 255.255.255.0)", "ADDR_gateway(testfw, 192.168.2.1)")
  }

  "Exported rules" should "be extracted" in {
    val addresses = Extractor.extractRules(testFile("w_control.pf"))
    addresses should startWith("(        :auth (")
  }
}
