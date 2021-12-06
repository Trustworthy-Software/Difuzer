package lu.uni.trux.difuzer.utils;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.FilenameUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import soot.Body;
import soot.Local;
import soot.Scene;
import soot.SootClass;
import soot.SootMethodRef;
import soot.Type;
import soot.Unit;
import soot.Value;
import soot.jimple.CaughtExceptionRef;
import soot.jimple.IdentityStmt;
import soot.jimple.Jimple;

/*-
 * #%L
 * Difuzer
 * 
 * %%
 * Copyright (C) 2021 Jordan Samhi
 * University of Luxembourg - Interdisciplinary Centre for
 * Security Reliability and Trust (SnT) - TruX - All rights reserved
 *
 * %%
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Lesser Public License for more details.
 * 
 * You should have received a copy of the GNU General Lesser Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/lgpl-2.1.html>.
 * #L%
 */

public class Utils {

	private static Logger logger = LoggerFactory.getLogger(Utils.class);
	
	private static int localNum = 0;

	public static Local addLocalToBody(Body b, Type t) {
		Local l = Jimple.v().newLocal(getNextLocalName(), t);
		b.getLocals().add(l);
		return l;
	}

	public static SootMethodRef getMethodRef(String className, String methodName) {
		return Scene.v().getSootClass(className).getMethod(methodName).makeRef();
	}

	private static String getNextLocalName() {
		return "loc"  + localNum++;
	}

	public static String getBasename(String path) {
		return String.format("%s.%s", FilenameUtils.getBaseName(path), FilenameUtils.getExtension(path));
	}

	public static String getBasenameWithoutExtension(String path) {
		return FilenameUtils.getBaseName(path);
	}

	// Inspired by Flowdroid
	public static boolean isSystemClass(String className) {
		return (className.startsWith("android.") || className.startsWith("java.") || className.startsWith("javax.")
				|| className.startsWith("sun.") || className.startsWith("org.omg.")
				|| className.startsWith("org.w3c.dom.") || className.startsWith("com.google.")
				|| className.startsWith("com.android.") || className.startsWith("androidx."));
	}

	public static void deleteFile(String filename) {
		File f = new File(filename);
		if(f.delete()) { 
			logger.info(String.format("%s successfully deleted", filename));
		} else { 
			logger.info(String.format("Failed to delete %s", filename));
		} 
	}

	public static String getClassNameFromSignature(String sig) {
		String tmp = sig.split(" ")[0];
		return tmp.substring(1, tmp.length() - 1);
	}

	public static String getMethodNameFromSignature(String sig) {
		String tmp = sig.split(" ")[2];
		return tmp.substring(0, tmp.indexOf("("));
	}

	public static String getReturnNameFromSignature(String sig) {
		return sig.split(" ")[1];
	}

	public static List<String> getParametersNamesFromSignature(String sig) {
		String tmp = sig.split(" ")[2];
		String params = tmp.substring(tmp.indexOf("(") + 1, tmp.indexOf(")"));
		String[] paramsArray = params.split(",");
		List<String> parameters = new ArrayList<String>();
		for(int i = 0 ; i < paramsArray.length ; i++) {
			parameters.add(paramsArray[i]);
		}
		return parameters;
	}
	
	public static boolean isCaugthException(Unit u) {
		if(u instanceof IdentityStmt) {
			IdentityStmt is = (IdentityStmt) u;
			Value rightOp = is.getRightOp();
			if(rightOp instanceof CaughtExceptionRef) {
				return true;
			}
		}
		return false;
	}
	
	private static List<SootClass> getAllSuperClasses(SootClass sootClass) {
		List<SootClass> classes = new ArrayList<SootClass>();
		SootClass superClass = null;
		if (sootClass.hasSuperclass()) {
			superClass = sootClass.getSuperclass();
			classes.add(superClass);
			classes.addAll(getAllSuperClasses(superClass));
		}
		return classes;
	}

	public static String getComponentType(SootClass sc) {
		List<SootClass> classes = getAllSuperClasses(sc);
		for(SootClass c : classes) {
			switch (c.getName()) {
			case Constants.ANDROID_APP_ACTIVITY : return Constants.ACTIVITY;
			case Constants.ANDROID_CONTENT_BROADCASTRECEIVER : return Constants.BROADCAST_RECEIVER;
			case Constants.ANDROID_CONTENT_CONTENTPROVIDER : return Constants.CONTENT_PROVIDER;
			case Constants.ANDROID_APP_SERVICE : return Constants.SERVICE;
			}
		}
		return Constants.NON_COMPONENT;
	}
}