import unittest
import subprocess
import sys
import os
import tempfile


class TestMainProfileArgument(unittest.TestCase):
    """Tests for --profile command line argument."""

    def test_profile_argument_accepted(self):
        """Test that --profile argument is accepted by argument parser."""
        # Run with --help to verify argument is recognized without running emulator
        result = subprocess.run(
            [sys.executable, "-m", "sun4m", "--help"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("--profile", result.stdout)
        self.assertIn("cProfile", result.stdout)

    def test_profile_default_filename(self):
        """Test that --profile uses default filename when no file specified."""
        # Check that help mentions default filename
        result = subprocess.run(
            [sys.executable, "-m", "sun4m", "--help"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        )
        self.assertIn("profile.stats", result.stdout)


if __name__ == "__main__":
    unittest.main()
