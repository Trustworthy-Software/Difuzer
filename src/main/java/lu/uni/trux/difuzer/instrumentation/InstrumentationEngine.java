package lu.uni.trux.difuzer.instrumentation;

import java.util.Iterator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.profiler.StopWatch;

import heros.InterproceduralCFG;
import lu.uni.trux.difuzer.ResultsAccumulator;
import lu.uni.trux.difuzer.files.BuildFieldsManager;
import lu.uni.trux.difuzer.files.LibrariesManager;
import lu.uni.trux.difuzer.utils.CommandLineOptions;
import lu.uni.trux.difuzer.utils.Utils;
import soot.Body;
import soot.PatchingChain;
import soot.Scene;
import soot.SootClass;
import soot.SootField;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.AbstractStmtSwitch;
import soot.jimple.AssignStmt;
import soot.jimple.FieldRef;
import soot.jimple.IfStmt;
import soot.jimple.Stmt;
import soot.jimple.infoflow.ipc.IIPCManager;

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

public class InstrumentationEngine implements IIPCManager{

	CommandLineOptions options;

	private Logger logger = LoggerFactory.getLogger(InstrumentationEngine.class);
	private boolean instrumentation_performed = false;

	private void initializeNewClasses() {
		IfClassGenerator.v().generateClass();
		BuildClassGenerator.v().generateClass();
	}

	@Override
	public boolean isIPC(Stmt sCallSite, InterproceduralCFG<Unit, SootMethod> cfg) {
		return false;
	}

	@Override
	public void updateJimpleForICC() {
		if(!this.isInstrumentation_performed()) {
			StopWatch swAnalysis = new StopWatch("Instrumentation");
			swAnalysis.start("Instrumentation");
			this.initializeNewClasses();
			for(SootClass sc : Scene.v().getApplicationClasses()) {
				if(!Utils.isSystemClass(sc.getName()) && sc.isConcrete()) {
					if(!LibrariesManager.v().contains(sc.getName())) {
						for(final SootMethod sm : sc.getMethods()) {
							if(sm.isConcrete() && !sm.isPhantom()) {
								final Body b = sm.retrieveActiveBody();
								if(sm.isConcrete()) {
									final PatchingChain<Unit> units = b.getUnits();
									for(Iterator<Unit> iter = units.snapshotIterator(); iter.hasNext();) {
										final Unit u = iter.next();
										u.apply(new AbstractStmtSwitch() {
											public void caseIfStmt(IfStmt stmt) {
												Unit newUnit = UnitGenerator.v().generateIfMethodCall(stmt, sm);
												if(newUnit != null) {
													logger.debug(String.format("Generating if method for if statement: %s", stmt));
													units.insertBefore(newUnit, stmt);
													b.validate();
													logger.debug(String.format("If method successfully generated: %s", newUnit));
													ResultsAccumulator.v().incrementIfCount();
												}
											}
											public void caseAssignStmt(AssignStmt stmt) {
												Value rop = stmt.getRightOp();
												if(rop instanceof FieldRef) {
													FieldRef fr = (FieldRef) rop;
													SootField sf = fr.getField();
													if(BuildFieldsManager.v().contains(sf.getSignature())) {
														Unit newUnit = UnitGenerator.v().generateBuildMethodCall(
																stmt.getLeftOp(), 
																sf);
														if(newUnit != null) {
															logger.debug(String.format("Generating build method for field: %s", stmt));
															units.insertAfter(newUnit, stmt);
															b.validate();
															logger.debug(String.format("Build method successfully generated: %s", newUnit));
															ResultsAccumulator.v().incrementBuildCount();
														}
													}
												}
											}
										});
									}
								}
							}
						}
					}
				}
			}
			this.setInstrumentation_performed(true);
			swAnalysis.stop();
			ResultsAccumulator.v().setInstrumentationElapsedTime((int) (swAnalysis.elapsedTime() / 1000000000));
		}
	}

	public boolean isInstrumentation_performed() {
		return instrumentation_performed;
	}

	public void setInstrumentation_performed(boolean instrumentation_performed) {
		this.instrumentation_performed = instrumentation_performed;
	}
}
