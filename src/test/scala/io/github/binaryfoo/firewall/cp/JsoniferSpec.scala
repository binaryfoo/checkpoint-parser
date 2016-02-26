package io.github.binaryfoo.firewall.cp

import io.github.binaryfoo.firewall.cp.rules.FwrAddressRange

class JsoniferSpec extends FwSpec {

  "JSON" should "be made" in {
    val rules = RuleParser.parse(contentsOf("wo_control.W"))
    val json = Jsonifier.toJson(rules)
    json shouldBe contentsOf("wo_control.json")
  }

  "Ip address range" should "become a 2 element list" in {
    val range = FwrAddressRange("10.0.0.1", "10.0.0.9")
    val json = Jsonifier.toJson(range)
    json shouldBe """["10.0.0.1","10.0.0.9"]"""
  }
}
