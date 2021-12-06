package lu.uni.trux.difuzer.instrumentation;

import java.util.ArrayList;
import java.util.List;

import lu.uni.trux.difuzer.files.SourcesSinksManager;
import lu.uni.trux.difuzer.utils.Constants;
import lu.uni.trux.difuzer.utils.Utils;
import soot.SootField;
import soot.SootMethod;
import soot.SootMethodRef;
import soot.Type;
import soot.Unit;
import soot.Value;
import soot.jimple.AbstractStmtSwitch;
import soot.jimple.AssignStmt;
import soot.jimple.ConditionExpr;
import soot.jimple.Constant;
import soot.jimple.IfStmt;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.Jimple;
import soot.jimple.Stmt;
import soot.toolkits.graph.BriefUnitGraph;

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

public class UnitGenerator {
	private static UnitGenerator instance;

	private UnitGenerator() {}

	public static UnitGenerator v() {
		if(instance == null) {
			instance = new UnitGenerator();
		}
		return instance;
	}

	public Unit generateIfMethodCall(IfStmt stmt, SootMethod sm) {
		ConditionExpr condition = (ConditionExpr) stmt.getCondition();
		List<Value> args = new ArrayList<Value>();
		List<Type> types = new ArrayList<Type>();
		Value op1 = condition.getOp1(),
				op2 = condition.getOp2();
		String symbol = condition.getSymbol();
		
		if((op1.toString().equals(Constants.NULL) || op2.toString().equals(Constants.NULL)) && (symbol.equals(Constants.EQUALS) || symbol.equals(Constants.DIFFERENT))) {
			return null;
		}
		
		LocalFinder lf = new LocalFinder(sm);
		List<Value> locals = new ArrayList<Value>();
		if(op1.toString().startsWith("$z")) {
			locals.addAll(lf.findBooleanOrigin(op1, stmt));
		}
		if(op2.toString().startsWith("$z")) {
			locals.addAll(lf.findBooleanOrigin(op2, stmt));
		}
		args.add(op1);
		args.add(op2);
		args.addAll(locals);
		
		for(Value v : args) {
			types.add(v.getType());
		}
		
		SootMethod newIfMethod = IfClassGenerator.v().generateIfMethod(types);
		SootMethodRef ref = Utils.getMethodRef(Constants.IF_CLASS, newIfMethod.getSubSignature());
		SourcesSinksManager.v().addSink(ref.resolve());
		Unit u = Jimple.v().newInvokeStmt(Jimple.v().newStaticInvokeExpr(
				ref, args));
		return u;
	}
	
	public Unit generateBuildMethodCall(Value leftOp, SootField field) {
		SootMethod newBuildMethod = BuildClassGenerator.v().generateBuildMethod(field.getName());
		SootMethodRef ref = Utils.getMethodRef(Constants.BUILD_CLASS, newBuildMethod.getSubSignature());
		SourcesSinksManager.v().addSource(ref.resolve());
		Unit u = Jimple.v().newAssignStmt(leftOp, Jimple.v().newStaticInvokeExpr(
				ref, new ArrayList<Value>()));
		return u;
	}

	public class LocalFinder {

		private SootMethod method;

		public LocalFinder(SootMethod sm) {
			this.method = sm;
		}

		public List<Value> findBooleanOrigin(Value v, Stmt  stmt) {
			List<Value> locals = new ArrayList<Value>();
			BriefUnitGraph bug = new BriefUnitGraph(method.retrieveActiveBody());
			for(Unit pred : bug.getPredsOf(stmt)) {
				this.getLocalsFromBoolean(pred, v, new ArrayList<Unit>(), locals, bug);
			}
			return locals;
		}

		private void getLocalsFromBoolean(Unit u, final Value v, final List<Unit> visitedUnits, final List<Value> locals, BriefUnitGraph bug) {
			visitedUnits.add(u);
			u.apply(new AbstractStmtSwitch() {
				public void caseAssignStmt(AssignStmt stmt) {
					Value leftOp = stmt.getLeftOp();
					if(leftOp.equals(v)) {
						Value rightOp = stmt.getRightOp();
						if(rightOp instanceof InvokeExpr) {
							InvokeExpr ie = (InvokeExpr) rightOp;
							if(ie instanceof InstanceInvokeExpr) {
								InstanceInvokeExpr iie = (InstanceInvokeExpr) ie;
								Value base = iie.getBase();
								if(!locals.contains(base)) {
									locals.add(base);
								}
							}
							for(Value arg : ie.getArgs()) {
								if(!(arg instanceof Constant)) {
									if(!locals.contains(arg)) {
										locals.add(arg);
									}
								}
							}
						}
					}
				}
			});
			for(Unit pred : bug.getPredsOf(u)) {
				if(!visitedUnits.contains(pred)) {
					this.getLocalsFromBoolean(pred, v, visitedUnits, locals, bug);
				}
			}
		}
	}
}
