import io.shiftleft.semanticcpg.language._
import java.io.PrintWriter

@main def exec(
    cpgFile: String,
    methodList: String,   
    fileList:   String,   
    outFile:    String
): Unit = {

  importCpg(cpgFile)

  val methods = methodList.split(",").toList
  val files   = fileList.split(",").toList

  if (methods.length != files.length) {
    System.err.println(
      s"ERROR: methodList (${methods.length}) and fileList (${files.length}) length mismatch"
    )
    sys.exit(1)
  }

  val writer = new PrintWriter(outFile)
  try {
    methods.zip(files).foreach { case (m, f) =>
      val startLine = cpg.method
        .filter(mtd => mtd.code != "<empty>" && mtd.code != "<global>" && mtd.name == m)
        .map(_.lineNumber.getOrElse(0))
        .l
        .headOption
        .getOrElse(0)
      writer.println(s"$f,$m,$startLine")
    }
  } finally {
    writer.close()
  }
  println(s"✓ Wrote ${methods.size} entries to $outFile")
  // cpg.graph().storage().close()
}
