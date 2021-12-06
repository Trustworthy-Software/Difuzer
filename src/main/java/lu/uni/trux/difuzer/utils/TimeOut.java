package lu.uni.trux.difuzer.utils;

/*-
 * #%L
 * TSOpen - Open-source implementation of TriggerScope
 * 
 * Paper describing the approach : https://seclab.ccs.neu.edu/static/publications/sp2016triggerscope.pdf
 * 
 * %%
 * Copyright (C) 2019 Jordan Samhi
 * University of Luxembourg - Interdisciplinary Centre for
 * Security Reliability and Trust (SnT) - All rights reserved
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

import java.util.Calendar;
import java.util.Timer;
import java.util.TimerTask;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import lu.uni.trux.difuzer.ResultsAccumulator;

public class TimeOut {

	private Timer timer;
	private TimerTask exitTask = null;
	private int timeout;

	protected Logger logger = LoggerFactory.getLogger(this.getClass());

	public TimeOut(int n, boolean hasRaw, String appName) {
		this.timer = new Timer();
		this.exitTask = new TimerTask() {
			@Override
			public void run() {
				logger.warn("Timeout reached !");
				logger.warn("Ending program...");
				ResultsAccumulator.v().setAnalysisElapsedTime(timeout);
				ResultsAccumulator.v().setAppName(Utils.getBasenameWithoutExtension(appName));
				if(hasRaw) {
					ResultsAccumulator.v().printVectorResults();
				}else {
					ResultsAccumulator.v().printTriggersResults();
				}
				System.exit(0);
			}
		};
		this.timeout = n != 0 ? n : 60;
	}

	public void trigger() {
		Calendar c = Calendar.getInstance();
		c.add(Calendar.MINUTE, this.timeout);
		this.timer.schedule(this.exitTask, c.getTime());
	}

	public void cancel() {
		this.timer.cancel();
	}

	public int getTimeout() {
		return this.timeout;
	}
}
