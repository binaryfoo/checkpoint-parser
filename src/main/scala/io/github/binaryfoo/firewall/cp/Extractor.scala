package io.github.binaryfoo.firewall.cp

import scala.io.Source

object Extractor {

  def extractRules(fileName: String): String = {
    extractRules(Source.fromFile(fileName))
  }

  def extractRules(source: Source): String = {
    try {
      var inRules = false
      source.getLines().filter { line =>
        if (line.startsWith("export {")) {
          inRules = true
          false
        } else if (line.startsWith(")")) {
          inRules = false
          true
        } else {
          inRules
        }
      }.mkString
    } finally {
      source.close()
    }
  }

  def extractAddressLines(fileName: String): List[String] = {
    val source = Source.fromFile(fileName)
    try {
      source.getLines().filter { line =>
        line.startsWith("ADDR_")
      }.toList
    } finally {
      source.close()
    }
  }

}
