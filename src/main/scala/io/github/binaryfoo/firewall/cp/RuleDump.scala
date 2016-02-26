package io.github.binaryfoo.firewall.cp

import io.github.binaryfoo.firewall.cp.rules._

object RuleDump {
  def toString(rule: FwrValue, buf: StringBuilder = new StringBuilder(), indent: String = ""): String = {
    rule match {
      case FwrObject(tag, values) =>
        buf.append(indent).append("(").append(tag).append(":")
        values match {
          case List(v: FwrLiteral) => buf.append(" ").append(v)
          case List(v: FwrAddressRange) => buf.append(" ").append(v)
          case List(v: FwrTableRef) => buf.append(" ").append(v)
          case _ =>
            for (value <- values) {
              buf.append("\n")
              toString(value, buf, indent + "  ")
            }
        }
        buf.append(")")
      case other =>
        buf.append(indent).append(rule)
    }
    buf.toString()
  }
}
