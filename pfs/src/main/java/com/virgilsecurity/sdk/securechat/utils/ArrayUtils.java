package com.virgilsecurity.sdk.securechat.utils;

import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

public class ArrayUtils {

	public static boolean isInList(final List<byte[]> list, final byte[] candidate) {

		for (final byte[] item : list) {
			if (Arrays.equals(item, candidate)) {
				return true;
			}
		}
		return false;
	}

	public static class ArrayComparator implements Comparator<byte[]> {
		@Override
		public int compare(byte[] o1, byte[] o2) {
			int result = 0;
			int maxLength = Math.max(o1.length, o2.length);
			for (int index = 0; index < maxLength; index++) {
				byte o1Value = index < o1.length ? o1[index] : 0;
				byte o2Value = index < o2.length ? o2[index] : 0;
				int cmp = Byte.compare(o1Value, o2Value);
				if (cmp != 0) {
					result = cmp;
					break;
				}
			}
			return result;
		}
	}

}
