package io.github.binaryfoo.firewall.cp

import java.nio.file.{Files, Paths}

import org.scalatest.{FlatSpec, Matchers}

class FwSpec extends FlatSpec with Matchers {

  def read(fileName: String): String = {
    new String(Files.readAllBytes(Paths.get(testFile(fileName))))
  }

  def testFile(fileName: String): String = {
    s"src/test/resources/$fileName"
  }

}
