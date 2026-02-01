
import unittest
import time
import os
from unittest.mock import MagicMock, patch, mock_open
from pathlib import Path

# Fix imports
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from vulnguard.pkg.scanner.scanner import Scanner, ScanResult
from vulnguard.pkg.advisor.llm_client import get_shared_http_client, _http_client_pool, _http_client_last_access, MAX_POOL_SIZE

class TestPerformance(unittest.TestCase):

    def setUp(self):
        self.scanner = Scanner(benchmark_dir="dummy_dir")
        self.scanner.logger = MagicMock()
        # Clean up pool for isolation
        _http_client_pool.clear()
        _http_client_last_access.clear()

    @patch("builtins.open", new_callable=mock_open, read_data="id: rule1\nbenchmark: test")
    @patch("yaml.safe_load")
    @patch("jsonschema.validate")
    @patch("pathlib.Path.exists")
    def test_rule_caching(self, mock_exists, mock_validate, mock_yaml, mock_file):
        """Verify that rules are loaded from disk only once."""
        mock_exists.return_value = True
        mock_yaml.return_value = {"id": "rule1", "benchmark": "test"}
        
        # First load
        rule1 = self.scanner._load_rule("test_rule.yaml")
        self.assertIsNotNone(rule1)
        
        # Second load
        rule2 = self.scanner._load_rule("test_rule.yaml")
        self.assertIsNotNone(rule2)
        
        # Verify file only opened once
        mock_file.assert_called_once()
        # Verify yaml load only happened once
        mock_yaml.assert_called_once()
        
        # Verify result identity (same object)
        self.assertIs(rule1, rule2)

    def test_parallel_scanning(self):
        """Verify that scan_all runs in parallel."""
        # Mock scan_rule to check sleep time
        def slow_scan(rule_id):
            time.sleep(0.1) # Sleep 100ms
            return ScanResult(
                rule_id=rule_id, 
                benchmark="TEST", 
                compliant=True, 
                expected_state="", 
                actual_state="", 
                check_output=""
            )
        
        self.scanner.scan_rule = slow_scan
        
        # Run 10 rules. Sequential would take 1.0s.
        # With 4 workers, should take approx 0.3s (10/4 = 2.5 chunks => 0.3s)
        
        start_time = time.time()
        results = self.scanner.scan_all(rule_ids=[f"rule_{i}" for i in range(10)])
        duration = time.time() - start_time
        
        self.assertEqual(len(results), 10)
        
        # Assert faster than sequential (with some buffer)
        self.assertLess(duration, 0.9, f"Parallel scan took {duration}s, expected < 0.9s for 10 x 0.1s tasks")
        print(f"Parallel scan of 10 rules took {duration:.4f}s")

    @patch("httpx.Client")
    def test_http_pool_eviction(self, mock_httpx):
        """Verify that HTTP client pool respects MAX_POOL_SIZE and evicts LRU."""
        # Set a small MAX_POOL_SIZE for testing if possible, or use module default (10)
        target_size = MAX_POOL_SIZE
        
        # Fill the pool
        for i in range(target_size):
            url = f"https://api.example.com/{i}"
            get_shared_http_client(url)
            time.sleep(0.01) # Ensure distinct timestamps
            
        self.assertEqual(len(_http_client_pool), target_size)
        
        # Determine the oldest key (should be .../0)
        oldest_url = "https://api.example.com/0"
        self.assertIn(oldest_url, _http_client_pool)
        
        # Add one more (should trigger eviction of oldest)
        new_url = f"https://api.example.com/{target_size}"
        get_shared_http_client(new_url)
        
        # Check size is still capped
        self.assertEqual(len(_http_client_pool), target_size)
        
        # Verify oldest was evicted
        self.assertNotIn(oldest_url, _http_client_pool)
        self.assertIn(new_url, _http_client_pool)

if __name__ == '__main__':
    unittest.main()
