import os
import json
import tempfile
import subprocess
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT, ResultKeyValueSection

class WebcrackService(ServiceBase):
    def __init__(self, config=None):
        super(WebcrackService, self).__init__(config)
        self.webcrack_path = "/opt/al_service/node_modules/webcrack"
        self.log.info("WebcrackService initialized")

    def start(self):
        self.log.debug("Webcrack service started")
        try:
            node_version = subprocess.check_output(["node", "--version"]).decode().strip()
            npm_version = subprocess.check_output(["npm", "--version"]).decode().strip()
            self.log.debug(f"Node.js version: {node_version}")
            self.log.debug(f"npm version: {npm_version}")
            
            if os.path.exists(self.webcrack_path):
                self.log.debug(f"Webcrack found at: {self.webcrack_path}")
                pkg_json = os.path.join(self.webcrack_path, "package.json")
                if os.path.exists(pkg_json):
                    with open(pkg_json) as f:
                        pkg_info = json.load(f)
                        self.log.debug(f"Webcrack version: {pkg_info.get('version')}")
            else:
                self.log.error(f"Webcrack not found at: {self.webcrack_path}")
                raise Exception(f"Webcrack not installed at {self.webcrack_path}")
        except Exception as e:
            self.log.error(f"Error during service start: {str(e)}")
            raise

    def execute(self, request):
        result = Result()
        
        try:
            # Get parameters from manifest
            deobfuscate_code = request.get_param('deobfuscate_code')
            unminify_code = request.get_param('unminify_code')
            unpack_bundles = request.get_param('unpack_bundles')

            # Get file path and read content
            file_path = request.file_path
            self.log.debug(f"Processing file: {file_path}")
            
            try:
                # Try to detect encoding
                with open(file_path, 'rb') as f:
                    raw_content = f.read()
                    # Check for BOM
                    if raw_content.startswith(b'\xef\xbb\xbf'):
                        encoding = 'utf-8-sig'
                    elif raw_content.startswith(b'\xff\xfe') or raw_content.startswith(b'\xfe\xff'):
                        encoding = 'utf-16'
                    else:
                        encoding = 'utf-8'
                    
                    self.log.debug(f"Detected encoding: {encoding}")
                    js_content = raw_content.decode(encoding)
                    self.log.debug(f"Input file size: {len(js_content)} bytes")
                    
            except UnicodeDecodeError as e:
                self.log.error(f"Failed to decode with {encoding}: {str(e)}")
                try:
                    # Fallback to latin-1 which can decode any byte sequence
                    js_content = raw_content.decode('latin-1')
                    self.log.debug("Fallback to latin-1 encoding successful")
                except Exception as e:
                    self.log.error(f"Failed to decode with fallback encoding: {str(e)}")
                    raise

            # Create temporary directory for output
            with tempfile.TemporaryDirectory() as temp_dir:
                self.log.debug(f"Created temp directory: {temp_dir}")
                
                output_path = os.path.join(self.working_directory, "deobfuscated.js")
                analysis_path = os.path.join(temp_dir, "analysis.json")
                script_path = os.path.join(temp_dir, "run_webcrack.mjs")
                input_path = os.path.join(temp_dir, "input.js")
                
                # Write preprocessed input file with detected encoding
                with open(input_path, 'w', encoding=encoding) as f:
                    f.write(js_content)
                self.log.debug(f"Wrote input file with {encoding} encoding")
                
                # Create Node.js script for webcrack
                script_content = f'''
import {{ webcrack }} from '/opt/al_service/node_modules/webcrack/dist/index.js';
import fs from 'fs';

function logError(error) {{
    console.error('Error details:');
    console.error('- Message:', error.message);
    console.error('- Name:', error.name);
    if (error.code) console.error('- Code:', error.code);
    if (error.pos) console.error('- Position:', error.pos);
    if (error.loc) console.error('- Location:', JSON.stringify(error.loc));
    if (error.stack) console.error('- Stack:', error.stack);
}}

(async () => {{
    try {{
        console.log('Reading input file...');
        const input = fs.readFileSync(process.argv[2], 'utf8');
        console.log(`Input file read successfully, size: ${{input.length}}`);
        
        console.log('Starting webcrack analysis...');
        const result = await webcrack(input, {{
            jsx: true,
            unpack: {str(unpack_bundles).lower()},
            unminify: {str(unminify_code).lower()},
            deobfuscate: {str(deobfuscate_code).lower()},
            mangle: (id) => id.startsWith('_0x'),  // Only mangle obfuscated identifiers
            tolerant: true,  // Added tolerant mode
            sourceType: 'unambiguous'  // Allow more flexible parsing
        }});
        console.log('Analysis completed successfully');
        
        console.log('Writing deobfuscated code...');
        fs.writeFileSync(process.argv[3], result.code);
        console.log('Deobfuscated code written successfully');
        
        console.log('Preparing analysis results...');
        const analysis = {{
            hasBundle: result.bundle !== null,
            bundleType: result.bundle ? result.bundle.type : null,
            transformations: result.transformations || []
        }};
        
        console.log('Writing analysis results...');
        fs.writeFileSync(process.argv[4], JSON.stringify(analysis, null, 2));
        console.log('Analysis results written successfully');
        
    }} catch (error) {{
        logError(error);
        // Write partial results if available
        try {{
            if (error.partialResult) {{
                console.log('Writing partial results...');
                fs.writeFileSync(process.argv[3], error.partialResult.code || '');
                fs.writeFileSync(process.argv[4], JSON.stringify({{
                    hasBundle: false,
                    bundleType: null,
                    transformations: error.partialResult.transformations || [],
                    error: {{
                        message: error.message,
                        location: error.loc
                    }}
                }}, null, 2));
            }}
        }} catch (e) {{
            console.error('Failed to write partial results:', e);
        }}
        process.exit(1);
    }}
}})();
'''
                with open(script_path, 'w') as f:
                    f.write(script_content)
                
                # Run webcrack analysis with increased memory limit for large files
                cmd = ["node", "--max-old-space-size=4096", "--experimental-modules", script_path, input_path, output_path, analysis_path]
                self.log.debug(f"Executing command: {' '.join(cmd)}")
                
                process = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    cwd=temp_dir,
                    env={**os.environ, 'NODE_PATH': '/opt/al_service/node_modules'}
                )
                
                # Create main section
                main_section = ResultSection(
                    title_text="Webcrack JavaScript Analysis Results",
                    body_format=BODY_FORMAT.TEXT
                )

                # Always try to read analysis results, even if process failed
                analysis_data = None
                if os.path.exists(analysis_path):
                    try:
                        with open(analysis_path, 'r') as f:
                            analysis_data = json.load(f)
                    except Exception as e:
                        self.log.error(f"Failed to read analysis results: {str(e)}")

                if process.returncode != 0:
                    error_msg = f"Webcrack analysis encountered issues:\nStdout: {process.stdout}\nStderr: {process.stderr}"
                    self.log.error(error_msg)
                    
                    error_section = ResultSection(
                        title_text="Analysis Issues",
                        body_format=BODY_FORMAT.TEXT
                    )
                    error_section.add_line(error_msg)
                    main_section.add_subsection(error_section)
                    
                    # If we have partial results, still try to process them
                    if analysis_data and analysis_data.get('error'):
                        error_info = analysis_data['error']
                        error_section.add_line(f"\nError details:")
                        error_section.add_line(f"Message: {error_info.get('message', 'Unknown')}")
                        if error_info.get('location'):
                            error_section.add_line(f"Location: {json.dumps(error_info['location'])}")

                # Process analysis results if available
                if analysis_data:
                    # Add bundle detection section
                    if analysis_data.get('hasBundle') and analysis_data.get('bundleType'):
                        bundle_section = ResultKeyValueSection(
                            title_text="JavaScript Bundle Detected"
                        )
                        bundle_section.set_item("Bundle Type", analysis_data.get('bundleType'))
                        bundle_section.set_heuristic(3)
                        main_section.add_subsection(bundle_section)
                        self.log.debug("Added bundle detection section")

                    # Add transformations section
                    if analysis_data.get('transformations'):
                        trans_section = ResultSection(
                            title_text="Applied Transformations",
                            body_format=BODY_FORMAT.TEXT
                        )
                        for t in analysis_data.get('transformations', []):
                            trans_section.add_line(f"- {t}")
                        main_section.add_subsection(trans_section)
                        self.log.debug("Added transformations section")

                        # Check for obfuscator.io patterns
                        if any('obfuscator.io' in t.lower() for t in analysis_data.get('transformations', [])):
                            obf_section = ResultSection(
                                title_text="Obfuscator.io Patterns Detected",
                                body_format=BODY_FORMAT.TEXT
                            )
                            obf_section.set_heuristic(2)
                            main_section.add_subsection(obf_section)
                            self.log.debug("Added obfuscator detection section")

                # Read and process deobfuscated code if available
                if os.path.exists(output_path):
                    try:
                        with open(output_path, 'r') as f:
                            deobfuscated = f.read()
                            
                        if deobfuscated and deobfuscated.strip() != js_content.strip():
                            request.add_extracted(output_path, "deobfuscated.js", "Deobfuscated and unminified JavaScript code from Webcrack")
                            
                            code_section = ResultSection(
                                title_text="Deobfuscated Code Extracted",
                                body_format=BODY_FORMAT.TEXT
                            )
                            code_section.add_line("The original JavaScript code was successfully deobfuscated and unminified.")
                            code_section.add_line("The resulting code has been extracted for further analysis.")
                            code_section.set_heuristic(1)
                            main_section.add_subsection(code_section)
                            self.log.debug("Extracted deobfuscated code and added section")
                    except Exception as e:
                        self.log.error(f"Failed to process deobfuscated code: {str(e)}")

                # Only add the main section if it has subsections
                if main_section.subsections:
                    result.add_section(main_section)
                    self.log.debug("Added main section with subsections")
                else:
                    # If no results were found, add an informational section
                    info_section = ResultSection(
                        title_text="Analysis Results",
                        body_format=BODY_FORMAT.TEXT
                    )
                    info_section.add_line("No significant changes or patterns were detected in the JavaScript code.")
                    result.add_section(info_section)
                    self.log.debug("Added info section (no changes detected)")

        except Exception as e:
            error_msg = f"Error analyzing JavaScript: {str(e)}"
            self.log.error(error_msg)
            error_section = ResultSection(
                title_text="Analysis Error",
                body_format=BODY_FORMAT.TEXT
            )
            error_section.add_line(error_msg)
            result.add_section(error_section)

        request.result = result
        self.log.debug("Service execution completed")
