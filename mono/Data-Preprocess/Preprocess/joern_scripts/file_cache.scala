import io.shiftleft.semanticcpg.language._
import java.io.PrintWriter

@main def exec(cpgFile: String, outFile: String): Unit = {
  importCpg(cpgFile)

  val names: List[String] = cpg.file.name.l.distinct

  def esc(s: String): String =
    s.replace("\\", "\\\\").replace("\"", "\\\"")
  val json = names.map(n => s""""${esc(n)}"""").mkString("[", ",", "]")

  new PrintWriter(outFile) {
    write(json)
    close()
  }

  println(s" Wrote ${names.size} entries to $outFile")
} 