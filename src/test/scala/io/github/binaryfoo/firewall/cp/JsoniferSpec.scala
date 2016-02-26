package io.github.binaryfoo.firewall.cp

class JsoniferSpec extends FwSpec {

  "JSON" should "be made" in {
    val rules = RuleParser.parse(read("wo_control.W"))
    val json = Jsonifier.toJson(rules)
    json shouldBe read("wo_control.json")
  }
}
