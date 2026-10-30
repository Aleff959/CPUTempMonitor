import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from monitor_core import CorsairSensorFilter


class TestCorsairSensorFilter(unittest.TestCase):
    def test_filter_initialization(self):
        f = CorsairSensorFilter()
        self.assertIsNone(f.smoothed_val)
        self.assertIsNone(f.last_display_int)
        self.assertEqual(f.get_display_int(), 0)

    def test_single_value_initialization(self):
        f = CorsairSensorFilter()
        disp = f.get_display_int(25.4)
        self.assertEqual(disp, 25)
        self.assertAlmostEqual(f.smoothed_val, 25.4)

    def test_jitter_elimination_at_integer_boundary(self):
        """
        Simulate real-world boundary oscillation around 24.5%:
        24.4, 25.1, 24.3, 25.2, 24.4, 25.0
        Without filter: display flips 24 -> 25 -> 24 -> 25 -> 24 -> 25
        With Corsair filter & hysteresis: display stays rock solid!
        """
        f = CorsairSensorFilter(slow_alpha=0.20, fast_alpha=0.75, fast_threshold=5.0, hysteresis=0.65)
        
        # Starts at 24.8 -> round to 25
        f.get_display_int(24.8)
        self.assertEqual(f.last_display_int, 25)

        # Micro-oscillations:
        jitter_sequence = [24.3, 25.2, 24.2, 25.1, 24.4, 25.0, 24.3]
        for val in jitter_sequence:
            disp = f.get_display_int(val)
            self.assertEqual(disp, 25, f"Display should remain solid at 25 during micro-fluctuation {val}, got {disp}")

    def test_fast_response_on_real_step_change(self):
        """
        When a real workload starts (e.g. 25% -> 80%), the filter
        must react immediately with fast_alpha without lag.
        """
        f = CorsairSensorFilter(slow_alpha=0.20, fast_alpha=0.75, fast_threshold=5.0, hysteresis=0.65)
        f.get_display_int(25.0)
        self.assertEqual(f.last_display_int, 25)

        # Step jump to 80% (diff = 55.0 >= fast_threshold 5.0)
        disp = f.get_display_int(80.0)
        # Expected smoothed: 0.75 * 80 + 0.25 * 25 = 66.25
        self.assertGreaterEqual(disp, 66)
        
        # Second tick at 80%
        disp2 = f.get_display_int(80.0)
        self.assertGreaterEqual(disp2, 76)

    def test_bounds_clamping(self):
        f1 = CorsairSensorFilter()
        disp_low = f1.get_display_int(-15.0)
        self.assertEqual(disp_low, 0)

        f2 = CorsairSensorFilter()
        disp_high = f2.get_display_int(1250.0)
        self.assertEqual(disp_high, 999)


if __name__ == "__main__":
    unittest.main()
