package io.github.binaryfoo.firewall.cp

import scala.io.Source

object Main {

  def main(args: Array[String]) {
    val source = if (args.length == 1) {
      Source.fromFile(args(0))
    } else {
      Source.fromInputStream(System.in)
    }
    val exported = Extractor.extractRules(source)
    val rules = RuleParser.parse(exported)
    println(Jsonifier.toJson(rules))
  }
}
