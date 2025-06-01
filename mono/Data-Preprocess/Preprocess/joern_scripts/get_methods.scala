// val fileNameOpt = method.file.name.headOption
// val sameFile = method.caller
//   .filterNot(_.name.startsWith("<"))
//   .filter(c => c.file.name.headOption == fileNameOpt)
//   .name
//   .dedup
//   .take(8)
//   .toList

// val others = method.caller
//   .filterNot(_.name.startsWith("<"))
//   .filter(c => c.file.name.headOption != fileNameOpt)
//   .name
//   .dedup
//   .filterNot(sameFile.contains)
//   .take(8 - sameFile.size)
//   .toList

// val callers = sameFile ++ others
// writer.println(s"${method.name} s"${callees.mkString(" ")} ${callees.mkString(" ")})
import java.io.{File, PrintWriter}

@main def exec(codeFile: String, outFile: String, lineNumbers: String) = {
  importCode(codeFile)
  val lines = lineNumbers.split(",").map(_.toInt)
  val vulnerableMethods = cpg.method
    .filter(n => {
      val start = n.lineNumber.getOrElse(0)
      val end = n.lineNumberEnd.getOrElse(start)
      lines.exists(line => line >= start && line <= end)
    })
    .dedup
    .filter(n => n.name.nonEmpty && n.name.head != '<')
    .l

  val writer = new PrintWriter(new File(outFile))
  try {
    vulnerableMethods.foreach { method =>
      val callees = method.callee
        .filterNot(m => m.name.contains("<"))
        .name
        .dedup
        .toList
      
      writer.println(s"${method.name} ${callees.mkString(" ")}")
    }
  } finally {
    writer.close()
  }
}

