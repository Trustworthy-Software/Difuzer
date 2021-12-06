package lu.uni.trux.difuzer.triggers;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import lu.uni.trux.difuzer.utils.Utils;
import soot.Body;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.IfStmt;
import soot.jimple.Stmt;
import soot.jimple.infoflow.solver.cfg.InfoflowCFG;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.SimpleDominatorsFinder;

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

public class Trigger {

	protected SootMethod method;
	protected Body body;
	protected InfoflowCFG icfg;
	protected BriefUnitGraph graph;
	protected IfStmt condition;
	protected List<Stmt> stmtsDominatedByCondition;
	protected Set<Unit> branchOne;
	protected Set<Unit> branchTwo;
	protected Set<Unit> bothBranches;

	protected Trigger() {
		this.setStmtsDominatedByCondition(new ArrayList<Stmt>());
		this.setBranchOne(new HashSet<Unit>());
		this.setBranchTwo(new HashSet<Unit>());
		this.setBothBranches(new HashSet<Unit>());
	}

	public Trigger(IfStmt i, InfoflowCFG icfg) {
		this();
		this.initializeTrigger(i, icfg);
	}


	protected void initializeTrigger(IfStmt i, InfoflowCFG icfg) {
		this.setIcfg(icfg);
		this.setCondition(i);
		this.generateGraph();
		this.generateGuardedStmts();
		this.generateBranches();
	}

	private void generateBranches() {
		List<Unit> successors = new ArrayList<Unit>();
		Unit succ = null;
		for(Unit u: this.graph.getSuccsOf(condition)) {
			if(!Utils.isCaugthException(u)) {
				successors.add(u);
			}
		}
		for(int i = 0 ; i < successors.size() ; i++) {
			succ = successors.get(i);
			// Branch One
			Set<Unit> intersection = null;
			if(i == 0) {
				this.getBranch(succ, this.branchOne);
			}
			// Branch Two
			else if(i == 1) {
				this.getBranch(succ, this.branchTwo);
			}
			intersection = new HashSet<Unit>(this.branchOne);
			intersection.retainAll(this.branchTwo);
			this.branchOne.removeAll(intersection);
			this.branchTwo.removeAll(intersection);
		}
		this.bothBranches.addAll(this.branchOne);
		this.bothBranches.addAll(this.branchTwo);
	}

	private void getBranch(Unit u, Set<Unit> list) {
		if(!list.contains(u) && this.stmtsDominatedByCondition.contains(u)) {
			list.add(u);
			for(Unit succ: this.graph.getSuccsOf(u)) {
				this.getBranch(succ, list);
			}
		}
	}

	protected void generateGuardedStmts() {
		SimpleDominatorsFinder<Unit> pdf = new SimpleDominatorsFinder<Unit>(this.graph);
		if(body != null) {
			for(Unit u : body.getUnits()) {
				if(pdf.isDominatedBy(u, condition) && !u.equals(condition)) {
					this.stmtsDominatedByCondition.add((Stmt)u);
				}
			}
		}
	}

	protected void generateGraph() {
		method = this.icfg.getMethodOf(this.condition);
		body = null;
		if(method.isConcrete()) {
			body = method.retrieveActiveBody();
			this.setGraph(new BriefUnitGraph(body));
		}
	}

	public InfoflowCFG getIcfg() {
		return icfg;
	}

	public void setIcfg(InfoflowCFG icfg) {
		this.icfg = icfg;
	}

	public BriefUnitGraph getGraph() {
		return graph;
	}

	public void setGraph(BriefUnitGraph graph) {
		this.graph = graph;
	}

	public IfStmt getCondition() {
		return condition;
	}

	public void setCondition(IfStmt condition) {
		this.condition = condition;
	}

	public List<Stmt> getStmtsDominatedByCondition() {
		return stmtsDominatedByCondition;
	}

	public void setStmtsDominatedByCondition(List<Stmt> stmtsDominatedByCondition) {
		this.stmtsDominatedByCondition = stmtsDominatedByCondition;
	}

	public SootMethod getMethod() {
		return method;
	}

	public void setMethod(SootMethod method) {
		this.method = method;
	}

	public Body getBody() {
		return body;
	}

	public void setBody(Body body) {
		this.body = body;
	}

	public Set<Unit> getBranchOne() {
		return branchOne;
	}

	public void setBranchOne(Set<Unit> branchOne) {
		this.branchOne = branchOne;
	}

	public Set<Unit> getBranchTwo() {
		return branchTwo;
	}

	public void setBranchTwo(Set<Unit> branchTwo) {
		this.branchTwo = branchTwo;
	}

	public Set<Unit> getBothBranches() {
		return bothBranches;
	}

	public void setBothBranches(Set<Unit> bothBranches) {
		this.bothBranches = bothBranches;
	}
}
