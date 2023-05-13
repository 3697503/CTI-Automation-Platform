import capa
import capa.main
import capa.engine
import capa.rules

# Path to the executable to analyze
path_to_executable = "redline.exe"

# Analyze the executable with capa
# rules = capa.check()
capabilities, meta = capa.engine.analyze_file(path_to_executable, rules)
capa.engine.
# Render the results to a string in Markdown format
markdown_report = capa.render.render_markdown(capabilities, meta)

# Print the report to the console
print(markdown_report)
