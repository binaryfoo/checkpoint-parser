package io.github.binaryfoo.firewall.cp

package object rules {

  type Tag = String

  sealed trait FwrValue

  // The {F7034704-6787-4FCF-A522-320C1EA52DF0} in
  // :chkpf_uid ("{F7034704-6787-4FCF-A522-320C1EA52DF0}")
  case class FwrLiteral(value: String) extends FwrValue

  // : None
  object FwrNone extends FwrValue

  // : net-224.0.0.0
  case class FwrTableRef(name: String) extends FwrValue

  // : ("<10.1.0.0, 10.1.0.255>")
  case class FwrAddressRange(start: String, end: String) extends FwrValue

  // In :auth ()
  //   tag = auth
  //   value = empty
  //
  // In :chkpf_uid ("{F7034704-6787-4FCF-A522-320C1EA52DF0}")
  //   tag = chkpf_uid
  //   value = List(FwrValue("{F7034704-6787-4FCF-A522-320C1EA52DF0}"))
  //
  // In : (drop
  // :AdminInfo (
  // ... more
  //   tag = drop
  //   children starts with FwrField("AdminInfo"
  case class FwrObject(tag: Tag, values: List[FwrValue] = List.empty) extends FwrValue {
    def apply(field: String): Option[FwrObject] = {
      values.collectFirst {
        case o@FwrObject(childName, _) if childName == field => o
      }
    }
  }
}
