package tools;

public class StringJsonParser {

	public static final char[] START_MARK = { '\"', '{', '[', '\0' };
	public static final char[] END_MARK = { '\"', '}', ']', ',' };

	public static String getValue(String json, String key) {
		int posKey = json.indexOf(key);
		int posStart = json.indexOf(":", posKey + key.length());
		int markType;
		do {
			++posStart;
			if (posStart >= json.length())
				return null;
		} while ((markType = isStartMark(json, posStart)) < 0);
		int posEnd = -1;
		for (int i = posStart + 1, count = 0; i < json.length(); ++i) {
			if (json.charAt(i) == END_MARK[markType]) {
				if (count == 0) {
					posEnd = i;
					if (markType != 3)
						++posEnd;
					break;
				} else
					--count;
			}
			if (json.charAt(i) == START_MARK[markType])
				++count;
		}
		return json.substring(posStart, posEnd);
	}

	private static int isStartMark(String json, int pos) {
		for (int i = 0; i < START_MARK.length; ++i) {
			if (json.charAt(pos) == START_MARK[i])
				return i;
			if (('0' <= json.charAt(pos) && json.charAt(pos) <= '9')
					|| json.charAt(pos) == 't' || json.charAt(pos) == 'f')
				return 3;
		}
		return -1;
	}
}
