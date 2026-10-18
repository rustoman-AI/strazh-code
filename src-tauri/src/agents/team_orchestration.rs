use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamTopology {
    Single,
    LeadSubagent,
    StarTeam,
    MeshTeam,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskNodeSpec {
    pub id: String,
    pub depends_on: Vec<String>,
    pub ownership_keys: Vec<String>,
    pub estimated_execution_tokens: u32,
    pub estimated_coordination_tokens: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedTaskBudget {
    pub task_id: String,
    pub execution_tokens: u64,
    pub coordination_tokens: u64,
    pub total_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionBatch {
    pub index: usize,
    pub task_ids: Vec<String>,
    pub ownership_locks: Vec<String>,
    pub estimated_total_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionPlan {
    pub topological_order: Vec<String>,
    pub budgets: Vec<PlannedTaskBudget>,
    pub batches: Vec<ExecutionBatch>,
    pub total_estimated_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanError {
    EmptyTaskId,
    DuplicateTaskId(String),
    MissingDependency { task_id: String, dependency: String },
    SelfDependency(String),
    CycleDetected(Vec<String>),
}

pub fn build_conflict_aware_execution_plan(
    tasks: &[TaskNodeSpec],
    max_parallel: usize,
) -> Result<ExecutionPlan, PlanError> {
    let mut in_degree = HashMap::new();
    let mut graph = HashMap::new();
    let mut task_map = HashMap::new();

    for task in tasks {
        if task.id.is_empty() {
            return Err(PlanError::EmptyTaskId);
        }
        if task_map.insert(task.id.clone(), task).is_some() {
            return Err(PlanError::DuplicateTaskId(task.id.clone()));
        }
        in_degree.insert(task.id.clone(), 0);
        graph.insert(task.id.clone(), Vec::new());
    }

    for task in tasks {
        for dep in &task.depends_on {
            if dep == &task.id {
                return Err(PlanError::SelfDependency(task.id.clone()));
            }
            if !in_degree.contains_key(dep) {
                return Err(PlanError::MissingDependency {
                    task_id: task.id.clone(),
                    dependency: dep.clone(),
                });
            }
            graph.get_mut(dep).unwrap().push(task.id.clone());
            *in_degree.get_mut(&task.id).unwrap() += 1;
        }
    }

    let mut ready = Vec::new();
    for (id, &deg) in &in_degree {
        if deg == 0 {
            ready.push(id.clone());
        }
    }

    let mut topological_order = Vec::new();
    let mut batches = Vec::new();
    let mut budgets = Vec::new();
    let mut total_estimated_tokens = 0;
    let mut batch_index = 0;
    
    while !ready.is_empty() {
        let mut current_batch_tasks = Vec::new();
        let mut current_locks = HashSet::new();
        let mut batch_tokens = 0;
        let mut next_ready = Vec::new();

        ready.sort();

        let mut i = 0;
        while i < ready.len() && current_batch_tasks.len() < max_parallel {
            let candidate_id = &ready[i];
            let task = task_map[candidate_id];
            
            let has_conflict = task.ownership_keys.iter().any(|k| current_locks.contains(k));
            if !has_conflict {
                let cand = ready.remove(i);
                for k in &task.ownership_keys {
                    current_locks.insert(k.clone());
                }
                
                let exec_tok = task.estimated_execution_tokens as u64;
                let coord_tok = task.estimated_coordination_tokens as u64;
                let total = exec_tok + coord_tok;
                
                budgets.push(PlannedTaskBudget {
                    task_id: cand.clone(),
                    execution_tokens: exec_tok,
                    coordination_tokens: coord_tok,
                    total_tokens: total,
                });
                
                batch_tokens += total;
                current_batch_tasks.push(cand.clone());
                topological_order.push(cand.clone());
                
                for next_node in &graph[&cand] {
                    let deg = in_degree.get_mut(next_node).unwrap();
                    *deg -= 1;
                    if *deg == 0 {
                        next_ready.push(next_node.clone());
                    }
                }
            } else {
                i += 1;
            }
        }
        
        batches.push(ExecutionBatch {
            index: batch_index,
            task_ids: current_batch_tasks,
            ownership_locks: current_locks.into_iter().collect(),
            estimated_total_tokens: batch_tokens,
        });
        batch_index += 1;
        total_estimated_tokens += batch_tokens;

        ready.extend(next_ready);
    }

    if topological_order.len() != tasks.len() {
        let mut cycle_nodes = Vec::new();
        for (id, &deg) in &in_degree {
            if deg > 0 {
                cycle_nodes.push(id.clone());
            }
        }
        return Err(PlanError::CycleDetected(cycle_nodes));
    }

    Ok(ExecutionPlan {
        topological_order,
        budgets,
        batches,
        total_estimated_tokens,
    })
}
