package lu.uni.trux.difuzer.filters;

import java.util.ArrayList;
import java.util.List;

import lu.uni.trux.difuzer.files.KnownHSOsFile;
import lu.uni.trux.difuzer.triggers.Trigger;
import lu.uni.trux.difuzer.triggers.TriggerIfCall;
import soot.SootMethod;

public class KnownHSOsFilter extends FilterImpl {

	public KnownHSOsFilter(FilterImpl n, List<TriggerIfCall> triggers) {
		super(n, triggers);
	}

	@Override
	public void applyFilter() {
		List<Trigger> triggersToRemove = new ArrayList<Trigger>();
		for(TriggerIfCall t: this.triggers) {
			for(SootMethod source: t.getSources()) {
				if(KnownHSOsFile.v().isKnown(t.getMethod(), source)) {
					triggersToRemove.add(t);
				}
			}
		}
		this.filterTriggers(triggersToRemove);
	}

}
