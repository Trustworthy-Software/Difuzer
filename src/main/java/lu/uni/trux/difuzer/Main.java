package lu.uni.trux.difuzer;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.slf4j.profiler.StopWatch;

import lu.uni.trux.difuzer.ocsvm.PredictOCSVM;
import lu.uni.trux.difuzer.triggers.TriggerIfCall;
import lu.uni.trux.difuzer.utils.CommandLineOptions;
import lu.uni.trux.difuzer.utils.Constants;
import lu.uni.trux.difuzer.utils.TimeOut;
import lu.uni.trux.difuzer.utils.Utils;
import soot.Scene;

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

public class Main {
	public static void main(String[] args) throws Throwable {
		StopWatch swAnalysis = new StopWatch("Difuzer");
		swAnalysis.start("Difuzer");

		CommandLineOptions options = new CommandLineOptions(args);
		
		if(!options.hasRaw()) {
			System.out.println(String.format("%s v%s started on %s\n", Constants.DIFUZER, Constants.VERSION, new Date()));
		}
		
		int timeout;
		if(options.hasTimeout()) {
			timeout = options.getTimeout();
		}else {
			timeout = 60;
		}
		TimeOut to = new TimeOut(timeout, options.hasRaw(), options.getApk());
		to.trigger();

		FlowAnalysis fa = new  FlowAnalysis(options);
		List<TriggerIfCall> triggers = fa.run();

		ResultsAccumulator.v().setTriggersBeforeAnomalyDetection(triggers.size());

		double prediction;
		List<TriggerIfCall> triggersToRemove = new ArrayList<TriggerIfCall>();
		for(TriggerIfCall t: triggers) {
			FeatureVector fv = new FeatureVector(t, Scene.v().getCallGraph());
			prediction = PredictOCSVM.v().predict(fv);
			if(prediction == 1) {
				triggersToRemove.add(t);
			}
		}
		triggers.removeAll(triggersToRemove);
		
		ResultsAccumulator.v().setTriggersAfterAnomalyDetection(triggers.size());
		ResultsAccumulator.v().setTriggersFound(triggers);
		swAnalysis.stop();
		ResultsAccumulator.v().setAnalysisElapsedTime((int) (swAnalysis.elapsedTime() / 1000000000));
		ResultsAccumulator.v().setAppName(Utils.getBasenameWithoutExtension(options.getApk()));

		if(options.hasRaw()) {
			ResultsAccumulator.v().printVectorResults();
		}else {
			ResultsAccumulator.v().printTriggersResults();
		}
		to.cancel();
	}
}