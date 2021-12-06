package lu.uni.trux.difuzer.filters;

import java.util.List;

import lu.uni.trux.difuzer.triggers.Trigger;
import lu.uni.trux.difuzer.triggers.TriggerIfCall;

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

public abstract class FilterImpl implements Filter {
	
	private FilterImpl next;
	protected List<TriggerIfCall> triggers;
	
	public FilterImpl(FilterImpl n, List<TriggerIfCall> triggers) {
		this.next = n;
		this.triggers = triggers;
	}

	@Override
	public void apply() {
		this.applyFilter();
		if(!this.triggers.isEmpty() && this.next != null) {
			this.next.apply();
		}
	}
	
	@Override
	public void filterTriggers(List<Trigger> triggers) {
		this.triggers.removeAll(triggers);
	}
}
