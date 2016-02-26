(
        :rule (
                :src (
                        : Any
                )
                :dst (
                        : Any
                )
                :services (
                        : echo-reply
                        : echo-request
                )
                :action (
                        : (accept
                                :type (accept)
                                :color ("Dark green")
                                :macro (RECORD_CONN)
                                :icon-name (icon-accept)
                                :text-rid (61463)
                                :windows-color (green)
                        )
                )
                :track ()
                :install (
                        : testfw
                )
                :time (
                        : Any
                )
        )
        :rule (
                :src (
                        : Any
                )
                :dst (
                        : Any
                )
                :services (
                        : SSH
                )
                :action (
                        : (accept
                                :type (accept)
                                :color ("Dark green")
                                :macro (RECORD_CONN)
                                :icon-name (icon-accept)
                                :text-rid (61463)
                                :windows-color (green)
                        )
                )
                :track ()
                :install (
                        : testfw
                )
                :time (
                        : Any
                )
        )
        :rule (
                :src (
                        : Any
                )
                :dst (
                        : Any
                )
                :services (
                        : Any
                )
                :action (
                        : (drop
                                :type (drop)
                                :color (Firebrick)
                                :icon-name (icon-drop)
                                :text-rid (61465)
                                :windows-color (green)
                        )
                )
                :track (
                        : Long
                )
                :install (
                        : testfw
                )
                :time (
                        : Any
                )
        )
        :rulename (wo_control)
        :filename (wo_control.W)
)