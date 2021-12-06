package lu.uni.trux.difuzer.instrumentation;

import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;

import lu.uni.trux.difuzer.utils.Constants;
import soot.RefType;
import soot.SootMethod;
import soot.Type;
import soot.UnitPatchingChain;
import soot.jimple.Jimple;
import soot.jimple.JimpleBody;
import soot.jimple.NullConstant;

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

public class BuildClassGenerator extends Generator{

	private static BuildClassGenerator instance;
	private List<String> buildNameManaged;

	private BuildClassGenerator() {
		this.buildNameManaged = new ArrayList<String>();
	}

	public static BuildClassGenerator v() {
		if(instance == null) {
			instance = new BuildClassGenerator();
		}
		return instance;
	}

	public SootMethod generateBuildMethod(String buildName) {
		if(!this.buildNameManaged.contains(buildName)) {
			String methodName = String.format("%s%s", Constants.BUILD_METHOD_PREFIX, buildName);
			SootMethod sm = new SootMethod(methodName,
					new ArrayList<Type>(), RefType.v(Constants.JAVA_LANG_STRING), Modifier.PUBLIC | Modifier.STATIC);
			this.clazz.addMethod(sm);
			JimpleBody body = Jimple.v().newBody(sm);
			sm.setActiveBody(body);
			UnitPatchingChain units = body.getUnits();
			units.add(Jimple.v().newReturnStmt(NullConstant.v()));
			body.validate();
			this.buildNameManaged.add(buildName);
			return sm;
		}
		return this.clazz.getMethodByName(String.format("%s%s", Constants.BUILD_METHOD_PREFIX, buildName));
	}

	@Override
	protected String getClazz() {
		return Constants.BUILD_CLASS;
	}
}
