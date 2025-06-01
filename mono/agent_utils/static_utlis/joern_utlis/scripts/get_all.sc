import java.nio.file.{Files, Paths}
if (!Files.exists(Paths.get(save_dir))) {
  Files.createDirectories(Paths.get(save_dir))
}
val file_path = s"$save_dir/all_nodes.json"
cpg.all.toJsonPretty |> file_path 

println(s"All nodes have been saved to: $file_path")

