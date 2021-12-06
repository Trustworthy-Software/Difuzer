package lu.uni.trux.difuzer.instrumentation;

import java.lang.reflect.Modifier;
import java.util.ArrayList;

import lu.uni.trux.difuzer.utils.Constants;
import lu.uni.trux.difuzer.utils.Utils;
import soot.Local;
import soot.RefType;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Type;
import soot.UnitPatchingChain;
import soot.VoidType;
import soot.jimple.Jimple;
import soot.jimple.JimpleBody;

public abstract class Generator {
	protected SootClass clazz;
	
	public void generateClass() {
		this.clazz = new SootClass(this.getClazz(), Modifier.PUBLIC);
		this.clazz.setSuperclass(Scene.v().getSootClass(Constants.JAVA_LANG_OBJECT));
		Scene.v().addClass(this.clazz);
		this.clazz.setApplicationClass();
		this.generateInitMethod();
	}
	
	protected void generateInitMethod() {
		SootMethod sm = new SootMethod(Constants.INIT,
				new ArrayList<Type>(), VoidType.v(), Modifier.PUBLIC);
		JimpleBody body = Jimple.v().newBody(sm);
		sm.setActiveBody(body);
		UnitPatchingChain units = body.getUnits();
		Local thisLocal = Utils.addLocalToBody(body, RefType.v(this.getClazz()));
		units.add(Jimple.v().newIdentityStmt(thisLocal, Jimple.v().newThisRef(RefType.v(this.getClazz()))));
		units.add(Jimple.v().newInvokeStmt(
				Jimple.v().newSpecialInvokeExpr(thisLocal,
						Utils.getMethodRef(Constants.JAVA_LANG_OBJECT, Constants.INIT_METHOD_SUBSIG))));
		units.add(Jimple.v().newReturnVoidStmt());
		body.validate();
		this.clazz.addMethod(sm);
	}
	
	protected abstract String getClazz();
}
