// Joern 4.0.0
import io.circe.generic.semiauto._
import io.circe.syntax._
import io.circe.{Encoder, Json}
import io.shiftleft.semanticcpg.dotgenerator.{CdgGenerator, DotSerializer}
import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.{EngineContext, EngineConfig}
import io.joern.dataflowengineoss.DefaultSemantics
import java.nio.file.{Files, Paths, StandardOpenOption}

final case class GraphForFuncsFunction(
  function: String,
  file: String,
  id: Long,
  AST: List[nodes.AstNode],
  CFG: List[nodes.AstNode],
  PDG: List[List[nodes.AstNode]],
  CrossPDG: List[List[nodes.AstNode]],
  DDG: DotSerializer.Graph,
  CDG: DotSerializer.Graph
)

final case class GraphForFuncsResult(functions: List[GraphForFuncsFunction])

//  DotSerializer.Edge 
implicit val encodeDotSerializerEdge: Encoder[DotSerializer.Edge] = (edge: DotSerializer.Edge) =>
  Json.obj(
    ("src", Json.fromLong(edge.src.id)),
    ("dst", Json.fromLong(edge.dst.id)),
    ("label", Json.fromString(edge.edgeType))
  )

//  flatgraph.Edge 
implicit val encodeFlatGraphEdge: Encoder[flatgraph.Edge] = (edge: flatgraph.Edge) =>
  Json.obj(
    ("src", Json.fromLong(edge.src.id)),
    ("dst", Json.fromLong(edge.dst.id)),
    ("label", Json.fromString(edge.label))
  )

//  GraphForFuncsFunction 
implicit val funcEncoder: Encoder[GraphForFuncsFunction] = deriveEncoder

//  GraphForFuncsResult 
implicit val resultEncoder: Encoder[GraphForFuncsResult] = deriveEncoder


implicit val encodeDotSerializerGraph: Encoder[DotSerializer.Graph] = (graph: DotSerializer.Graph) =>
  Json.obj(
    ("nodes", Json.fromValues(graph.vertices.cast[nodes.AstNode].map(_.asJson).iterator.to(Iterable))),
    ("edges", Json.fromValues(graph.edges.map(_.asJson)))
  )

implicit val encodeNode: Encoder[nodes.AstNode] = (node: nodes.AstNode) =>
  Json.obj(
    ("id", Json.fromLong(node.id)),
    ("location", Json.obj(
      ("filename", Json.fromString(node.location.filename)),
      ("line", Json.fromInt(node.lineNumber.getOrElse(-1))),
      ("column", Json.fromInt(node.columnNumber.getOrElse(-1)))
    )),
    ("code", Json.fromString(node.code)),
    ("edges", Json.fromValues((node.inE("AST").toList ++ node.inE("CFG").toList ++ node.outE("AST").toList ++ node.outE("CFG").toList).map(_.asJson)))
  ) // AST, CFG only one string 




def buildCrossMethodPDG(methods: List[nodes.Method])(implicit context: EngineContext): List[List[nodes.AstNode]] = {
  // all may init data nodes
  val crossMethodSources = methods.flatMap { method =>
    method.parameter ++
    method.methodReturn ++
    method.call.nameNot("<operator>.*")
  }.dedup.distinct

  // all may use data nodes
  val crossMethodSinks = methods.flatMap { method =>
    method.call.name(".*(sink|dangerous).*") ++
    method.assignment.target
  }.dedup.distinct

  crossMethodSinks
    .reachableByFlows(crossMethodSources)
    .map(_.elements)
    .filter(_.nonEmpty)
    .distinct
    .toList
}


def getMethodGraph(method: nodes.Method, crossPaths: List[List[nodes.AstNode]])(implicit context: EngineContext): GraphForFuncsFunction = {
  println(s"Processing ${method.fullName}")
  // val input = scala.io.StdIn.readLine()

  val methodId = method.id
  
  // AST node
  val astNodes = method.ast.toList
  
  // CFG node
  val cfgNodes = method.cfgNode.toList
  
  // DDG
  val ddg = new io.joern.dataflowengineoss.dotgenerator.DdgGenerator().generate(method)
  
  // CDG
  val cdg = new CdgGenerator().generate(method)
  
  // PDG
  val parameters = method.parameter.toList
  
  val local = method
    .out(EdgeTypes.CONTAINS)
    .filter(_.label == NodeTypes.BLOCK)
    .out(EdgeTypes.AST)
    .filter(_.label == NodeTypes.LOCAL)
    .cast[nodes.Local]
    .l
  
  val sink = local
    .evalType(".*")
    .referencingIdentifiers
    .dedup
  
  val source = method
    .out(EdgeTypes.CONTAINS)
    .filter(_.label == NodeTypes.CALL)
    .cast[nodes.Call]
    .filter(!_.name.matches("<operator>.*"))
    .dedup
  
  // get PDG path
  val pdgPaths = sink
    .reachableByFlows(source)
    .l
    .map { path =>
      path.elements
        .map {
          case cfgNode @ (_: MethodParameterIn) => cfgNode.start.method.head
          case cfgNode                          => cfgNode
        }
        .filter(_.id != methodId)
    }
  

  // Cross PDG
  val relatedCrossPaths = crossPaths
  

  GraphForFuncsFunction(
    method.fullName,
    method.location.filename,
    methodId,
    astNodes,
    cfgNodes,
    pdgPaths,
    relatedCrossPaths,
    ddg,
    cdg
  )
}


val defaultSemantics = DefaultSemantics() 

val engineConfig = EngineConfig(
  maxCallDepth = 5,
  initialTable = None,
  shareCacheBetweenTasks = true, 
  maxArgsToAllow = 20,
  maxOutputArgsExpansion = 5
)

implicit val context: EngineContext = EngineContext(defaultSemantics, engineConfig)

// val targetMethods = cpg.method.fullName(".*(main|factorial|printResult).*").toList
// println(targetMethods)
val crossPaths = buildCrossMethodPDG(targetMethods)

val result = GraphForFuncsResult(
  targetMethods.map { method =>
    getMethodGraph(method, crossPaths)  
  }
)

result.asJson.noSpaces

// pdgResult.asJson.noSpaces


