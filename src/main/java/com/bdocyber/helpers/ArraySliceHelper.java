package com.bdocyber.helpers;

/**
 * Utility for slicing byte arrays.
 */
public final class ArraySliceHelper {

    private ArraySliceHelper() {
    }

    public static byte[] getArraySlice(byte[] array, int start, int end) {
        if (array == null || start < 0 || end > array.length || start > end) {
            throw new IllegalArgumentException("Invalid slice bounds");
        }
        byte[] slice = new byte[end - start];
        System.arraycopy(array, start, slice, 0, slice.length);
        return slice;
    }
}
