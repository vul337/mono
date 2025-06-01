import io.shiftleft.codepropertygraph.generated.nodes._
import scala.collection.mutable
import java.io.PrintWriter
import spray.json._
import DefaultJsonProtocol._
import ScalaReplPP.JsonProtocol.resultFormat
import scala.jdk.CollectionConverters._

case class Result(
  relatedMethod:     List[(String, String, String, String, Int)], // (filename, methodName, fullName, rawAst, depth)
  typeDefs:          List[(String, String)],
  globalVars:        List[String],
  importContext:     List[String],
  vulnerableMethods: List[(String, String, String, Int)],        // (filename, methodName, rawAst, line)
  visitedLines:      List[(Int, String, String)],                // (line, methodName, filename)
  visitedParams:     List[(String, String, String)]              // (paramCode, methodName, filename)
)

object JsonProtocol extends DefaultJsonProtocol {
  implicit val resultFormat: RootJsonFormat[Result] = jsonFormat7(Result)
}

object GraphTraversal {
  def bfs[N](
    start: Seq[N],
    neighbors: Seq[N => Iterable[N]],
    filter: N => Boolean
  ): Set[N] = {
    val visited = mutable.Set.empty[N]
    val queue   = mutable.Queue(start: _*)
    while (queue.nonEmpty) {
      val node = queue.dequeue()
      if (!visited(node) && filter(node)) {
        visited += node
        neighbors.foreach(fn => queue.enqueueAll(fn(node)))
      }
    }
    visited.toSet
  }
}

@main def exec(
  cpgFile:        String,
  outFile:        String,
  methodnameList: String,
  filename:       String,
  lineNumbers:    String
): Unit = {
  importCpg(cpgFile)

  val lines   = lineNumbers.split(",").map(_.toInt)
  val methods = methodnameList.split(",")
  val imports = cpg.file
    .filter(_.name.matches(s".*${filename}"))
    ._namespaceBlockViaAstOut
    ._astOut
    .collect { case i: Import => i.code }
    .distinct
    .toList

  val allVisitedLines  = mutable.Set.empty[(Int, String, String)]
  val allVisitedParams = mutable.Set.empty[(String, String, String)]
  val allCalleeMethods = mutable.Set.empty[(String, String, String, String, Int)]
  val allTypesDefs     = mutable.Set.empty[(String, String)]
  val allGlobalVars    = mutable.Set.empty[String]

  val vulns = cpg.method
    .filter(m => methods.contains(m.name))
    .filter(_.filename.matches(s".*${filename}"))
    .map(m => (m.filename, m.name, m.toList.dumpRaw.head, m.lineNumber.getOrElse(0)))
    .toList

  val inFns  = Seq[StoredNode => Iterable[StoredNode]](_. _reachingDefIn.toList, _. _cdgIn.toList, _. _argumentOut.toList)
  val outFns = Seq[StoredNode => Iterable[StoredNode]](_. _reachingDefOut.toList, _. _cdgOut.toList, _. _argumentOut.toList)
  def inTarget(n: StoredNode) = methods.contains(n.location.methodShortName)

  lines.foreach { ln =>
    val starts = cpg.method
      .filter(m => methods.contains(m.name))
      .filter(_.filename.matches(s".*${filename}"))
      .ast
      .lineNumber(ln)
      .toList

    if (starts.nonEmpty) {
      val forward  = GraphTraversal.bfs(starts, inFns, inTarget)
      val backward = GraphTraversal.bfs(starts, outFns, inTarget)

      (forward ++ backward).foreach { node =>
        val line = node.propertiesMap.asScala
          .get("LINE_NUMBER")
          .map(_.asInstanceOf[Integer].intValue())
          .getOrElse(0)
        val mtd  = node.location.methodShortName
        val fp   = node.location.filename
        allVisitedLines += ((line, mtd, fp))

        node match {
          case p: MethodParameterIn => allVisitedParams += ((p.code, mtd, fp))
          case _                    =>
        }

        node._callOut.cast[Method].foreach { m =>
          allCalleeMethods += ((m.filename, m.name, m.fullName, m.toList.dumpRaw.head, 1))
        }

        node._evalTypeOut._refOut.cast[TypeDecl].map(_.name).foreach { tname =>
          val base = tname.replaceAll("\\*", "")
          cpg.typeDecl(base)
            .filter(_.lineNumber.nonEmpty)
            .toList
            .headOption
            .foreach(td => allTypesDefs += ((td.code, td.name)))
        }
    
        node._refOut
          .filter(_.location.methodShortName == "<global>")
          .cast[Local]
          .foreach(l => allGlobalVars += l.code)
      }

      val maxDepth = 3
      val queue    = mutable.Queue(allCalleeMethods.toSeq: _*)
      val seen     = allCalleeMethods.map(c => (c._1, c._2)).to(mutable.Set)

      while (queue.nonEmpty) {
        val (fn, mn, full, raw, depth) = queue.dequeue()
        if (depth < maxDepth) {
          val nextLevel = cpg.method
            .name(mn)
            .filter(_.filename == fn)
            .callee
            .filterNot(_.filename.contains("<"))
            .map { m => (m.filename, m.name, m.fullName, m.toList.dumpRaw.head, depth + 1) }
            .dedup
            .toList
            .filterNot(cm => seen((cm._1, cm._2)))

          nextLevel.foreach { cm =>
            allCalleeMethods += cm
            queue.enqueue(cm)
            seen += ((cm._1, cm._2))
          }
        }
      }
    }
  }

  val result = Result(
    relatedMethod     = allCalleeMethods.toList,
    typeDefs          = allTypesDefs.toList,
    globalVars        = allGlobalVars.toList,
    importContext     = imports,
    vulnerableMethods = vulns,
    visitedLines      = allVisitedLines.toList,
    visitedParams     = allVisitedParams.toList
  )
  new PrintWriter(outFile) { write(result.toJson.prettyPrint); close() }
  println(s"$outFile saved.")
}
