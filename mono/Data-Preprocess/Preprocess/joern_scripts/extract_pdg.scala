// methodList（fullNameExact） AST/CFG/DDG/CDG/PDG

import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.DefaultSemantics
import io.joern.dataflowengineoss.queryengine.{EngineContext, EngineConfig}
import io.shiftleft.semanticcpg.dotgenerator.{CdgGenerator, DotSerializer}
import io.shiftleft.codepropertygraph.generated.nodes._
import spray.json._
import DefaultJsonProtocol._
import java.io.PrintWriter
import scala.jdk.CollectionConverters._

final case class AstNodeJson(id: Long, filename: String, line: Int, column: Int, code: String)
final case class EdgeJson(src: Long, dst: Long, label: String)
final case class GraphJson(nodes: List[AstNodeJson], edges: List[EdgeJson])
final case class FuncJson(
  fullName: String,
  file:     String,
  id:       Long,
  AST:      List[AstNodeJson],
  CFG:      List[AstNodeJson],
  PDG:      List[List[AstNodeJson]],
  Cross:    List[List[AstNodeJson]],
  DDG:      GraphJson,
  CDG:      GraphJson
)
final case class ResultJson(functions: List[FuncJson])

implicit val astFmt:  RootJsonFormat[AstNodeJson] = jsonFormat5(AstNodeJson)
implicit val edgeFmt: RootJsonFormat[EdgeJson]    = jsonFormat3(EdgeJson)
implicit val graphFmt:RootJsonFormat[GraphJson]   = jsonFormat2(GraphJson)
implicit val fnFmt:   RootJsonFormat[FuncJson]    = jsonFormat9(FuncJson)
implicit val resFmt:  RootJsonFormat[ResultJson]  = jsonFormat1(ResultJson)

@main def exec(
  cpgFile:    String,
  outFile:    String,
  methodList: String      
): Unit = {
  println(s"[DEBUG] exec start; methodList=$methodList")
  importCpg(cpgFile)

  val methods = methodList.split(",").map(_.trim).filter(_.nonEmpty)
  val targets = methods.toList.flatMap { fn =>
    val hits = cpg.method.fullNameExact(fn).toList
    println(s"  $fn → ${hits.size}")
    hits
  }
  if (targets.isEmpty) {
    new PrintWriter(outFile) { write(ResultJson(Nil).toJson.prettyPrint); close() }
    return
  }

  implicit val ctx: EngineContext = {
    val sem = DefaultSemantics()
    val cfg = EngineConfig(
      maxCallDepth           = 5,
      initialTable           = None,
      shareCacheBetweenTasks = true,
      maxArgsToAllow         = 20,
      maxOutputArgsExpansion = 5
    )
    EngineContext(sem, cfg)
  }

  def buildCrossPDG(ms: List[Method]): List[List[AstNode]] = {
    val srcs = ms.flatMap(m => m.parameter ++ m.methodReturn ++ m.call.nameNot("<operator>.*")).distinct
    val snks = ms.flatMap(m => m.call.name(".*(sink|dangerous).*") ++ m.assignment.target).distinct
    snks.reachableByFlows(srcs)
      .toList
      .map(_.elements.toList)
      .filter(_.nonEmpty)
      .distinct
  }
  val cross = buildCrossPDG(targets)
  println(s"[DEBUG] crossPDG paths = ${cross.size}")

  // 4) 准备 DDG/CDG 生成器
  val ddgGen = new io.joern.dataflowengineoss.dotgenerator.DdgGenerator()
  val cdgGen = new CdgGenerator()

  def dot2json(g: DotSerializer.Graph): GraphJson = {
    val ns = g.vertices.cast[AstNode].toList.map { n =>
      AstNodeJson(n.id, n.location.filename, n.lineNumber.getOrElse(-1), n.columnNumber.getOrElse(-1), n.code)
    }
    val es = g.edges.toList.map(e => EdgeJson(e.src.id, e.dst.id, e.edgeType))
    GraphJson(ns, es)
  }

  def pdg2json(ps: List[List[AstNode]]): List[List[AstNodeJson]] =
    ps.map(_.map(n => AstNodeJson(n.id, n.location.filename, n.lineNumber.getOrElse(-1), n.columnNumber.getOrElse(-1), n.code)))

  val funcs = targets.map { m =>
    println(s"[DEBUG] processing ${m.fullName}")

    val astNodes = m.ast.toList
    val cfgNodes = m.cfgNode.toList
    println(s"[DEBUG]  AST=${astNodes.size}, CFG=${cfgNodes.size}")

    val ddg = ddgGen.generate(m)
    val cdg = cdgGen.generate(m)

    // dataflow PDG
    val srcs = m.out(EdgeTypes.CONTAINS).filter(_.label == NodeTypes.CALL)
                 .cast[Call].filterNot(_.name.matches("<operator>.*")).dedup
    val snks = m.out(EdgeTypes.CONTAINS).filter(_.label == NodeTypes.BLOCK)
                 .out(EdgeTypes.AST).filter(_.label == NodeTypes.LOCAL).cast[Local]
                 .evalType(".*").referencingIdentifiers.dedup
 

    val allPdg0 = snks.reachableByFlows(srcs)
      .toList
      .map(_.elements.toList.map {
        case p: MethodParameterIn => p.start.method.head
        case x                    => x
      }.filter(_.id != m.id))
      .filter(_.nonEmpty).distinct


    val maxPaths     = 10
    val maxPathNodes = 100
    val rawPdg = allPdg0
      .take(maxPaths)
      .map { path =>
        if (path.size > maxPathNodes) {
          println(s"[DEBUG]  PDG path too long (${path.size}), truncate to $maxPathNodes")
          path.take(maxPathNodes)
        } else path
      }


    FuncJson(
      m.fullName,
      m.location.filename,
      m.id,
      astNodes.map(n => AstNodeJson(n.id, n.location.filename, n.lineNumber.getOrElse(-1), n.columnNumber.getOrElse(-1), n.code)),
      cfgNodes.map(n => AstNodeJson(n.id, n.location.filename, n.lineNumber.getOrElse(-1), n.columnNumber.getOrElse(-1), n.code)),
      pdg2json(rawPdg),
      pdg2json(cross),
      dot2json(ddg),
      dot2json(cdg)
    )
  }

  val jsonAst = ResultJson(funcs).toJson
  new PrintWriter(outFile) {
    write(jsonAst.compactPrint)
    close()
  }

  println(s"[DEBUG] wrote ${funcs.size} function(s) → $outFile")
}
