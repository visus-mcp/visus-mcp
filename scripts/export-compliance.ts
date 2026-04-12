import fs from 'fs/promises';
import path from 'path';
import archiver from 'archiver';

const COMPLIANCE_ROOT = path.join(process.cwd(), 'docs/compliance');
const TECHNICAL_FILE = path.join(COMPLIANCE_ROOT, 'technical-file');
const ARTIFACTS = path.join(COMPLIANCE_ROOT, 'artifacts');

/**
 * Export Compliance Technical File as ZIP
 * Usage: tsx scripts/export-compliance.ts [output.zip]
 */
async function exportTechnicalFile(outputPath?: string): Promise<string> {
  outputPath = outputPath || path.join(ARTIFACTS, `visus-mcp-technical-file-v1.0-${Date.now()}.zip`);
  
  // Create artifacts if not exists
  await fs.mkdir(ARTIFACTS, { recursive: true });
  
  const archive = archiver('zip', { zlib: { level: 9 } });
  const output = fs.createWriteStream(outputPath);
  archive.pipe(output);
  
  // Add all technical-file contents
  const addFolderToArchive = async (folderPath: string, basePath: string) => {
    const entries = await fs.readdir(folderPath, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(folderPath, entry.name);
      const archivePath = path.relative(basePath, fullPath);
      
      if (entry.isDirectory()) {
        await addFolderToArchive(fullPath, basePath);
      } else {
        archive.file(fullPath, { name: archivePath });
      }
    }
  };
  
  await addFolderToArchive(TECHNICAL_FILE, COMPLIANCE_ROOT);
  
  // Add README.md as index
  archive.file(path.join(COMPLIANCE_ROOT, 'README.md'), { name: 'index.md' });
  
  // Finalize
  await archive.finalize();
  
  console.log(`Technical File exported: ${outputPath}`);
  return outputPath;
}

// CLI wrapper
const args = process.argv.slice(2);
if (args[0]) {
  exportTechnicalFile(args[0]).catch(console.error);
} else {
  exportTechnicalFile().then(console.log).catch(console.error);
}

export { exportTechnicalFile };
