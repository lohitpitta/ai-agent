"""
Parses package-lock.json files to extract dependency information.
Supports lockfileVersion 1, 2, and 3.
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class Dependency:
    """Represents a single npm dependency."""
    name: str
    version: str
    is_direct: bool
    source_file: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "is_direct": self.is_direct,
            "source_file": self.source_file
        }


class DependencyParser:
    """Parses package-lock.json files."""
    
    def parse_lockfile(self, lockfile_path: Path) -> List[Dependency]:
        """
        Parse a package-lock.json file and extract dependencies.
        
        Args:
            lockfile_path: Path to package-lock.json
            
        Returns:
            List of Dependency objects
        """
        try:
            with open(lockfile_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            # Log error but don't crash
            print(f"Warning: Failed to parse {lockfile_path}: {e}")
            return []
        
        lockfile_version = data.get("lockfileVersion", 1)
        
        if lockfile_version == 1:
            return self._parse_v1(data, str(lockfile_path))
        elif lockfile_version == 2:
            return self._parse_v2(data, str(lockfile_path))
        elif lockfile_version == 3:
            return self._parse_v3(data, str(lockfile_path))
        else:
            print(f"Warning: Unknown lockfileVersion {lockfile_version} in {lockfile_path}")
            return []
    
    def _parse_v1(self, data: Dict[str, Any], source_file: str) -> List[Dependency]:
        """Parse lockfileVersion 1 format."""
        dependencies = []
        
        # Direct dependencies are in "dependencies"
        direct_deps = set(data.get("dependencies", {}).keys())
        
        # All packages are in "dependencies" (nested structure)
        def extract_packages(deps_obj: Dict[str, Any], is_direct: bool = False):
            for name, info in deps_obj.items():
                version = info.get("version", "")
                if version:
                    dependencies.append(Dependency(
                        name=name,
                        version=version,
                        is_direct=(name in direct_deps),
                        source_file=source_file
                    ))
                
                # Recursively handle nested dependencies
                if "dependencies" in info:
                    extract_packages(info["dependencies"], False)
        
        extract_packages(data.get("dependencies", {}), True)
        return dependencies
    
    def _parse_v2(self, data: Dict[str, Any], source_file: str) -> List[Dependency]:
        """Parse lockfileVersion 2 format."""
        dependencies = []
        
        # Direct dependencies
        direct_deps = set(data.get("dependencies", {}).keys())
        
        # All packages are in "packages" with keys like "node_modules/package-name"
        packages = data.get("packages", {})
        
        for pkg_key, pkg_info in packages.items():
            # Skip the root package (empty key)
            if not pkg_key or pkg_key == "":
                continue
            
            # Extract package name from key
            # Format: "node_modules/package-name" or "node_modules/parent/node_modules/child"
            name = pkg_key.split("/")[-1]
            
            version = pkg_info.get("version", "")
            if version:
                dependencies.append(Dependency(
                    name=name,
                    version=version,
                    is_direct=(name in direct_deps),
                    source_file=source_file
                ))
        
        return dependencies
    
    def _parse_v3(self, data: Dict[str, Any], source_file: str) -> List[Dependency]:
        """Parse lockfileVersion 3 format (similar to v2)."""
        # v3 is structurally similar to v2 for our purposes
        return self._parse_v2(data, source_file)
