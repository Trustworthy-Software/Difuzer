package lu.uni.trux.difuzer.filters;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import lu.uni.trux.difuzer.files.SensitiveMethodsManager;
import lu.uni.trux.difuzer.triggers.Trigger;
import lu.uni.trux.difuzer.triggers.TriggerIfCall;
import soot.Body;
import soot.PatchingChain;
import soot.Scene;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.Stmt;
import soot.jimple.toolkits.callgraph.Edge;

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

public class SensitiveMethodsFilter extends FilterImpl {

	public SensitiveMethodsFilter(FilterImpl n, List<TriggerIfCall> triggers) {
		super(n, triggers);
	}

	@Override
	public void applyFilter() {
		List<Trigger> triggersToRemove = new ArrayList<Trigger>();
		boolean found;
		SootMethod sm = null;
		for(Trigger t : this.triggers) {
			found = false;
			for(Stmt stmt : t.getStmtsDominatedByCondition()) {
				if(stmt.containsInvokeExpr()) {
					sm = stmt.getInvokeExpr().getMethod();
					found = this.checkMethod(sm);
					if(found) {
						break;
					}
				}
			}
			if(!found) {
				triggersToRemove.add(t);
			}
		}
		this.filterTriggers(triggersToRemove);
	}

	private boolean checkMethod(SootMethod targetMethod) {
		if(SensitiveMethodsManager.v().contains(targetMethod.getSignature())) {
			return true;
		}else if(targetMethod.isConcrete()) {
			Body b = targetMethod.retrieveActiveBody();
			final PatchingChain<Unit> units = b.getUnits();
			for(Iterator<Unit> iter = units.snapshotIterator(); iter.hasNext();) {
				Stmt stmt = (Stmt) iter.next();
				if(stmt.containsInvokeExpr()) {
					SootMethod sm = stmt.getInvokeExpr().getMethod();
					Iterator<Edge> it = Scene.v().getCallGraph().edgesOutOf(sm);
					while(it.hasNext()) {
						Edge next = it.next();
						targetMethod = next.getTgt().method();
						if(targetMethod.getDeclaringClass().isApplicationClass()) {
							return checkMethod(targetMethod);
						}
					}
				}
			}
		}
		return false;
	}
}
