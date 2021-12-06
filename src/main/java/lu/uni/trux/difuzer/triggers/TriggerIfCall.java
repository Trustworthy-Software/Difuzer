package lu.uni.trux.difuzer.triggers;

import java.util.ArrayList;
import java.util.List;

import lu.uni.trux.difuzer.utils.Constants;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.Constant;
import soot.jimple.IfStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.infoflow.solver.cfg.InfoflowCFG;

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

public class TriggerIfCall extends Trigger {

	private List<SootMethod> sources;
	private List<Value> variablesUsedInCondition;
	private Unit ifMethodCall;
	
	public TriggerIfCall(Unit u, InfoflowCFG icfg, List<SootMethod> sources) {
		super();
		IfStmt i = this.generateCondition(u, icfg);
		this.setIfMethodCall(u);
		this.initializeTrigger(i, icfg);
		this.variablesUsedInCondition = new ArrayList<Value>();
		this.generateListOfVariablesUsed(u);
		this.setSources(sources);
	}

	private void generateListOfVariablesUsed(Unit u) {
		if(u instanceof InvokeStmt) {
			InvokeStmt inv = (InvokeStmt) u;
			InvokeExpr ie = inv.getInvokeExpr();
			if(ie.getMethod().getName().equals(Constants.IF_METHOD)) {
				for(Value v: ie.getArgs()) {
					if(!(v instanceof Constant)) {
						this.variablesUsedInCondition.add(v);
					}
				}
			}
		}
	}

	private IfStmt generateCondition(Unit u, InfoflowCFG icfg) {
		if(u instanceof InvokeStmt) {
			InvokeStmt inv = (InvokeStmt) u;
			if(inv.getInvokeExpr().getMethod().getName().equals(Constants.IF_METHOD)) {
				for(Unit unit : icfg.getSuccsOf(u)) {
					if(unit instanceof IfStmt) {
						return (IfStmt)unit;
					}
				}
			}
		}
		return null;
	}

	public List<SootMethod> getSources() {
		return sources;
	}

	public void setSources(List<SootMethod> sources) {
		this.sources = sources;
	}

	public List<Value> getVariablesUsedInCondition() {
		return variablesUsedInCondition;
	}

	public void setVariablesUsedInCondition(List<Value> variablesUsedInCondition) {
		this.variablesUsedInCondition = variablesUsedInCondition;
	}

	public Unit getIfMethodCall() {
		return ifMethodCall;
	}

	public void setIfMethodCall(Unit ifMethodCall) {
		this.ifMethodCall = ifMethodCall;
	}
}
