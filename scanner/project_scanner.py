"""
Recursively finds package.json and package-lock.json files in a project directory.
Skips node_modules, build, dist, and .git directories.
"""

from pathlib import Path
from typing import List


class ProjectScanner:
    """Scans project directories for npm manifest files."""
    
    SKIP_DIRS = {"node_modules", "build", "dist", ".git"}
    
    def find_manifests(self, project_path: Path) -> List[Path]:
        """
        Recursively find package.json and package-lock.json files.
        
        Args:
            project_path: Root directory to scan
            
        Returns:
            List of paths to package-lock.json files
        """
        if not isinstance(project_path, Path):
            project_path = Path(project_path)
        
        manifests = []
        
        for item in project_path.rglob("*"):
            # Skip directories we don't want to traverse
            if any(skip_dir in item.parts for skip_dir in self.SKIP_DIRS):
                continue
            
            # We only care about package-lock.json files
            if item.name == "package-lock.json" and item.is_file():
                manifests.append(item)
        
        return manifests
