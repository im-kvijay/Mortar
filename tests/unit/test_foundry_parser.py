
import unittest
from unittest.mock import patch, mock_open
from pathlib import Path
from src.cal.foundry_parser import FoundryConfigParser

class TestFoundryConfigParser(unittest.TestCase):
    
    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.read_text")
    def test_parse_basic_config(self, mock_read_text, mock_exists):
        mock_exists.return_value = True
        mock_read_text.return_value = 'src = "source"\ntest = "tests"\nlibs = ["lib", "node_modules"]'
        
        parser = FoundryConfigParser(Path("/tmp/project"))
        
        # on macos /tmp is /private/tmp. Compare string suffix or resolve.
        self.assertTrue(str(parser.src_dir).endswith("/tmp/project/source"))
        self.assertTrue(str(parser.test_dir).endswith("/tmp/project/tests"))
        self.assertTrue(str(parser.libs[0]).endswith("/tmp/project/lib"))

    @patch("pathlib.Path.exists", autospec=True)
    @patch("pathlib.Path.read_text")
    def test_parse_remappings_txt(self, mock_read_text, mock_exists):
        def side_effect(self_path):
            # self_path is the Path instance calling exists()
            path_str = str(self_path)
            if path_str.endswith("foundry.toml"):
                return False
            if path_str.endswith("remappings.txt"):
                return True
            if "openzeppelin-contracts" in path_str:
                return True
            return False
        mock_exists.side_effect = side_effect
        
        mock_read_text.return_value = '@openzeppelin/=lib/openzeppelin-contracts/'
        
        parser = FoundryConfigParser(Path("/tmp/project"))
        # @openzeppelin/ -> lib/openzeppelin-contracts/
        resolved = parser.resolve_import("@openzeppelin/contracts/token/ERC20.sol", Path("/tmp/project/src/Contract.sol"))
        # handle macos /private/tmp
        self.assertTrue(str(resolved).endswith("/tmp/project/lib/openzeppelin-contracts/contracts/token/ERC20.sol"))

    @patch("pathlib.Path.exists", autospec=True)
    @patch("pathlib.Path.read_text")
    def test_resolve_relative_import(self, mock_read_text, mock_exists):
        parser = FoundryConfigParser(Path("/tmp/project"))
        
        # import "./utils/Math.sol" from "src/Vault.sol"
        
        current_file = Path("/tmp/project/src/Vault.sol")
        import_path = "./utils/Math.sol"
        def side_effect(self_path):
            path_str = str(self_path)
            if "Math.sol" in path_str or "IVault.sol" in path_str:
                return True
            return False
        mock_exists.side_effect = side_effect
        
        resolved = parser.resolve_import(import_path, current_file)
        self.assertTrue(str(resolved).endswith("/tmp/project/src/utils/Math.sol"))
        
        # import "../interfaces/IVault.sol" from "src/strategies/Strategy.sol"
        current_file = Path("/tmp/project/src/strategies/Strategy.sol")
        import_path = "../interfaces/IVault.sol"
        
        resolved = parser.resolve_import(import_path, current_file)
        self.assertTrue(str(resolved).endswith("/tmp/project/src/interfaces/IVault.sol"))

if __name__ == '__main__':
    unittest.main()
