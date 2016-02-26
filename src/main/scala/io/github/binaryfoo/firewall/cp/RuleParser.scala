package io.github.binaryfoo.firewall.cp

import io.github.binaryfoo.firewall.cp.rules._

import scala.util.parsing.combinator.RegexParsers

class RuleParser extends RegexParsers {

  private var quoted = false

  override def skipWhitespace: Boolean = {
    if (quoted) false else super.skipWhitespace
  }

  def identifier: Parser[String] = """[-a-zA-Z0-9_.]+""".r

  def tag: Parser[String] = ":" ~> identifier

  def tableRef: Parser[FwrTableRef] = ": " ~> identifier ^^ { FwrTableRef }

  def ipAddress: Parser[String] = """[0-9.]+""".r

  def addressRange: Parser[FwrAddressRange] = ": (\"<" ~> (ipAddress ~ ("," ~> ipAddress)) <~ ">\")" ^^ {
    case start ~ end => FwrAddressRange(start, end)
  }

  def strayLiteral: Parser[FwrLiteral] = ": (" ~> (quotedLiteral | literal) <~ ")" ^^ { FwrLiteral }

  def quotedLiteral: Parser[String] = toggle("\"", true) ~> untilQuote <~ toggle("\"", false)

  def literal: Parser[String] = """[^") ]+""".r

  def untilQuote: Parser[String] = """[^"]+""".r

  def toggle(p: Parser[String], inQuote: Boolean): Parser[String] = {
    p.map { r =>
      quoted = inQuote
      r
    }
  }

  def emptyObject: Parser[FwrObject] = (tag <~ "()") ^^ { FwrObject(_) }

  def primitiveObject: Parser[FwrObject] = tag ~ ("(" ~> (quotedLiteral | literal) <~ ")") ^^ {
    case tag ~ literal => FwrObject(tag, List(FwrLiteral(literal)))
  }

  def compoundObject: Parser[FwrObject] = tag ~ ("(" ~> rep(fwrObject) <~ ")") ^^ {
    case tag ~ objs => FwrObject(tag, objs)
  }

  def namedObject: Parser[FwrObject] = (": (" ~> opt(identifier) ~ rep(fwrObject) <~ ")") ^^ {
    case Some(tag) ~ objs => FwrObject(tag, objs)
    case None ~ objs => FwrObject(null, objs)
  }

  def referenceObject: Parser[FwrObject] = (identifier ~ rep1(fwrObject)) ^^ {
    case tag ~ objs => FwrObject(tag, objs)
  }

  def fwrObject: Parser[FwrValue] = track(emptyObject | tableRef | addressRange | primitiveObject | compoundObject | strayLiteral | namedObject | referenceObject)

  def root: Parser[FwrObject] = "(" ~> rep(fwrObject) <~ ")" ^^ { objs => FwrObject(null, objs) }

  var lastOffset: Int = 0
  var lastResult: ParseResult[Any] = null

  def track[T](p: => Parser[T]): Parser[T] = Parser{ in =>
    val r = p(in)
    if (in.offset > lastOffset && r != null) {
      lastOffset = in.offset
      lastResult = r
//      println(lastOffset + " " + r)
    }
    r
  }
}

object RuleParser extends RuleParser {

  def parse(objs: String): FwrObject = {
    val result: RuleParser#ParseResult[FwrObject] = parse(root, objs)
    result match {
      case Success(root, _) => root
      case oops =>
        println(lastResult)
        println(oops)
        null
    }
  }

}
