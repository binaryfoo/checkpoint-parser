package io.github.binaryfoo.firewall.cp

import io.github.binaryfoo.firewall.cp.rules._

object Jsonifier {

  def toJson(obj: FwrValue): String = {
    obj match {
      case FwrObject(null, children) =>
        children.map(toJson).mkString("[", ",\n", "]")
      case FwrObject(name, List(FwrLiteral(value))) =>
        "{" + quote(name) + ":" + quote(value) + "}"
      case FwrObject(name, children) =>
        val kids = children.map(toJson).mkString("[", ",\n", "]")
        "{" + quote(name) + ":" + kids + "}"
      case FwrLiteral(value) => quote(value)
      case FwrNone => "null"
      case FwrTableRef(value) => quote(value)
      case FwrAddressRange(start, end) => quote(start + "-" + end)
    }
  }

  private def quote(s: String): String = "\"" + escape(s) + "\""

  private def escape(s: String): String = s.replace("""\""", """\\""")
}
