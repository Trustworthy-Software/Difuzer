package lu.uni.trux.difuzer.files;

import java.util.Arrays;

import lu.uni.trux.difuzer.utils.Constants;
import soot.SootMethod;

public class KnownHSOsFile extends FileLoader {

	private static KnownHSOsFile instance;

	private KnownHSOsFile () {
		super();
	}

	public static KnownHSOsFile v() {
		if(instance == null) {
			instance = new KnownHSOsFile();
		}
		return instance;
	}

	@Override
	protected String getFile() {
		return Constants.KNOWN_HSO_FILE;
	}
	
	public boolean isKnown(SootMethod method, SootMethod source) {
		for (String str: this.items) {
			String[] split = str.split(";");
			String m = split[0];
			String[] sources = split[1].split("\\|");
			for(String s: Arrays.asList(sources)) {
				if(method.getSignature().equals(m) && source.getSignature().equals(s)) {
					return true;
				}
			}
		}
		return false;
	}

}
