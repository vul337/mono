// Joern 4.0.0
import io.circe.generic.semiauto._
import io.circe.syntax._
import io.circe.{Encoder, Json}
import io.shiftleft.semanticcpg.dotgenerator.{CdgGenerator, DotSerializer}
import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import java.nio.file.{Files, Paths, StandardOpenOption}

final case class GraphForFuncsFunction(
  function: String,
  file: String,
  id: Long,
  AST: List[nodes.AstNode],
  CFG: List[nodes.AstNode],
  PDG: List[List[nodes.AstNode]],
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

def getMethodGraph(method: nodes.Method)(implicit context: EngineContext): GraphForFuncsFunction = {
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
  
  GraphForFuncsFunction(
    method.fullName,
    method.location.filename,
    methodId,
    astNodes,
    cfgNodes,
    pdgPaths,
    ddg,
    cdg
  )
}

// get pdg
implicit val context: EngineContext = EngineContext() 
// val method = cpg.method.id(111669149696L).head
val pdgResult = GraphForFuncsResult(List(getMethodGraph(method)))

// pdgResult.asJson.noSpaces

// println(jsonString)
// save to file
// save_dir = "/app/project/..."
// val save_dir = "/app/test"
val outputDir = s"$save_dir/extract_pdg"
val outputFile = s"$outputDir/${method.fullName}.json"
if (!Files.exists(Paths.get(outputDir))) {
  Files.createDirectories(Paths.get(outputDir))
}

Files.write(
  Paths.get(outputFile),
  pdgResult.asJson.spaces2.getBytes,
  StandardOpenOption.CREATE,
  StandardOpenOption.WRITE,
  StandardOpenOption.TRUNCATE_EXISTING
)
