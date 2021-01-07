from generic_hash_rearmed import (CH,
                                  MAJ,
                                  ROTR,
                                  leading_zeros,
                                  fill_message,
                                  SHR)

import unittest


class TestHashFunctions(unittest.TestCase):
    def test_SHR(self):
        self.assertEqual(SHR(0b0001100, 1), 0b0000110)

    def test_CH(self):
        self.assertEqual(CH(0b100, 0b010, 0b001), -0b0000110)

    def test_maj(self):
        self.assertEqual(MAJ(0b1, 0b1, 0b1), 0b1)

    def test_fill_message(self):
        self.assertTrue(len(fill_message("m")) % 512 == 0)

    def test_ROTR(self):
        self.assertEquals(ROTR(0b001100, 4),
                          0b11000000000000000000000000000000)

    def test_leading_zeros(self):
        self.assertTrue(len(leading_zeros(10)) == 10)


if __name__ == "__main__":
    unittest.main()
