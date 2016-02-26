package io.github.binaryfoo.firewall.cp

import io.github.binaryfoo.firewall.cp.RuleParser.Success
import io.github.binaryfoo.firewall.cp.rules.{FwrAddressRange, FwrLiteral, FwrObject, FwrTableRef}

class RuleParserSpec extends FwSpec {

  "Parser" should "parse primitive literal" in {
    val result = RuleParser.parse(RuleParser.primitiveObject, ":disabled (false)")
    result.get shouldBe FwrObject("disabled", List(FwrLiteral("false")))
  }

  it should "parse quoted literal" in {
    val result = RuleParser.parse(RuleParser.primitiveObject, ":chkpf_uid (\"{F7034704-6787-4FCF-A522-320C1EA52DF0}\")")
    result.get shouldBe FwrObject("chkpf_uid", List(FwrLiteral("{F7034704-6787-4FCF-A522-320C1EA52DF0}")))
  }

  it should "parse named object" in {
    val result = RuleParser.parse(RuleParser.namedObject,
      """: (rule-1
        |			:AdminInfo (
        |				:chkpf_uid ("{F7034704-6787-4FCF-A522-320C1EA52DF0}")
        |				:ClassName (security_rule)
        |			)
        |   )""".stripMargin)
    result.get.tag shouldBe "rule-1"
  }

  it should "parse table reference" in {
    val result = RuleParser.parse(RuleParser.tableRef, ": net-224.0.0.0")
    result.get shouldBe FwrTableRef("net-224.0.0.0")
  }

  it should "parse address range" in {
    val result = RuleParser.parse(RuleParser.addressRange, ": (\"<10.1.0.0, 10.1.0.255>\")")
    result.get shouldBe FwrAddressRange("10.1.0.0", "10.1.0.255")
  }

  it should "parse stray literal" in {
    val result = RuleParser.parse(RuleParser.strayLiteral, ": (\"1,0,AH,srv_name\")")
    result.get shouldBe FwrLiteral("1,0,AH,srv_name")
  }

  it should "work" in {
    val input =
      """(
        |	:auth ()
        |	:rules (
        |     :disabled (false)
        | )
        |)""".stripMargin
    val rules = RuleParser.parse(input)
    rules.values(0) shouldBe FwrObject("auth")
    rules.values(1) shouldBe FwrObject("rules", List(FwrObject("disabled", List(FwrLiteral("false")))))
  }

  it should "handle ) within quoted literal" in {
    val input = """: (asm_http_worm2_pattern
                  |	:type (str)
                  |	:val ("(cmd\.exe)|(root\.exe)")
                  |)
                  |""".stripMargin
    val Success(rules, _) = RuleParser.parse(RuleParser.fwrObject, input)
    rules shouldBe FwrObject("asm_http_worm2_pattern", List(FwrObject("type", List(FwrLiteral("str"))), FwrObject("val", List(FwrLiteral("(cmd\\.exe)|(root\\.exe)")))))
  }

  it should "handle space in a quoted literal" in {
    val input =
      """:http_sql_injection_reset_vals (
        |	: ("/")
        |	: (.)
        |	: (" ")
        |	: ("=")
        |	: ("%22")
        |	: ("'")
        |)""".stripMargin
    val Success(rules, _) = RuleParser.parse(RuleParser.fwrObject, input)
    rules shouldBe FwrObject("http_sql_injection_reset_vals", List(FwrLiteral("/"), FwrLiteral("."), FwrLiteral(" "), FwrLiteral("="), FwrLiteral("%22"), FwrLiteral("'")))
  }

  it should "handle ReferenceObject" in {
    val input =
      """:p2p_http_patterns_global (ReferenceObject
        |	:Table (asm)
        |	:Name (BittorrentHttpPatterns)
        |	:Uid ("{31681C15-8B8B-4BCE-A20A-7F60F8C9792E}")
        |)""".stripMargin
    val Success(rules, _) = RuleParser.parse(RuleParser.fwrObject, input)
    rules shouldBe FwrObject("p2p_http_patterns_global", List(FwrObject("ReferenceObject", List(FwrObject("Table", List(FwrLiteral("asm"))), FwrObject("Name", List(FwrLiteral("BittorrentHttpPatterns"))), FwrObject("Uid", List(FwrLiteral("{31681C15-8B8B-4BCE-A20A-7F60F8C9792E}")))))))
  }

  "wc_control.W" should "be parsed" in {
    val rules = RuleParser.parse(contentsOf("wo_control.W"))
    rules.values.length shouldBe 5
  }

  "w_control.pf" should "be parsed" in {
    val rules = RuleParser.parse(Extractor.extractRules(testFile("w_control.pf")))
    rules.values.length shouldBe 9
  }

}
