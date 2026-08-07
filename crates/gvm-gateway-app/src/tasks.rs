// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Task use cases.

use gvm_gateway_domain::{
    CreateTaskInput, GatewayError, ModifyTaskInput, Task, TaskAction, TaskPage, TaskQuery,
};

use crate::GatewayService;

impl GatewayService {
    /// Lists tasks for an authenticated session.
    pub async fn list_tasks(
        &self,
        session_token: &str,
        query: TaskQuery,
    ) -> Result<TaskPage, GatewayError> {
        self.execute_with_resource(
            "tasks.list",
            session_token,
            "list",
            "task",
            None,
            |session| async move { self.tasks.list_tasks(&session.token, &query).await },
        )
        .await
    }

    /// Creates a new task for an authenticated session.
    pub async fn create_task(
        &self,
        session_token: &str,
        input: CreateTaskInput,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "tasks.create",
            session_token,
            "create",
            "task",
            None,
            |session| async move { self.tasks.create_task(&session.token, input).await },
        )
        .await
    }

    /// Clones a task for an authenticated session.
    pub async fn clone_task(&self, session_token: &str, id: &str) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "tasks.clone",
            session_token,
            "create",
            "task",
            Some(id),
            |session| async move { self.tasks.clone_task(&session.token, id).await },
        )
        .await
    }

    /// Fetches a task for an authenticated session.
    pub async fn get_task(&self, session_token: &str, id: &str) -> Result<Task, GatewayError> {
        self.execute_with_resource(
            "tasks.get",
            session_token,
            "read",
            "task",
            Some(id),
            |session| async move { self.tasks.get_task(&session.token, id).await },
        )
        .await
    }

    /// Modifies a task for an authenticated session.
    pub async fn modify_task(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyTaskInput,
    ) -> Result<Task, GatewayError> {
        self.execute_with_resource(
            "tasks.modify",
            session_token,
            "modify",
            "task",
            Some(id),
            |session| async move { self.tasks.modify_task(&session.token, id, input).await },
        )
        .await
    }

    /// Deletes a task for an authenticated session.
    pub async fn delete_task(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "tasks.delete",
            session_token,
            "delete",
            "task",
            Some(id),
            |session| async move { self.tasks.delete_task(&session.token, id, ultimate).await },
        )
        .await
    }

    /// Starts a task for an authenticated session.
    pub async fn start_task(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<TaskAction, GatewayError> {
        self.execute_with_resource(
            "tasks.start",
            session_token,
            "start",
            "task",
            Some(id),
            |session| async move { self.tasks.start_task(&session.token, id).await },
        )
        .await
    }

    /// Stops a running task for an authenticated session.
    pub async fn stop_task(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "tasks.stop",
            session_token,
            "stop",
            "task",
            Some(id),
            |session| async move { self.tasks.stop_task(&session.token, id).await },
        )
        .await
    }

    /// Resumes a stopped task for an authenticated session.
    pub async fn resume_task(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<TaskAction, GatewayError> {
        self.execute_with_resource(
            "tasks.resume",
            session_token,
            "resume",
            "task",
            Some(id),
            |session| async move { self.tasks.resume_task(&session.token, id).await },
        )
        .await
    }

    /// Lists audits (compliance tasks) for an authenticated session.
    pub async fn list_audits(
        &self,
        session_token: &str,
        query: TaskQuery,
    ) -> Result<TaskPage, GatewayError> {
        self.execute_with_resource(
            "audits.list",
            session_token,
            "list",
            "audit",
            None,
            |session| async move { self.tasks.list_audits(&session.token, &query).await },
        )
        .await
    }

    /// Creates a new audit (compliance task) for an authenticated session.
    pub async fn create_audit(
        &self,
        session_token: &str,
        input: CreateTaskInput,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "audits.create",
            session_token,
            "create",
            "audit",
            None,
            |session| async move { self.tasks.create_audit(&session.token, input).await },
        )
        .await
    }

    /// Modifies an audit for an authenticated session.
    pub async fn modify_audit(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyTaskInput,
    ) -> Result<Task, GatewayError> {
        self.execute_with_resource(
            "audits.modify",
            session_token,
            "modify",
            "audit",
            Some(id),
            |session| async move { self.tasks.modify_audit(&session.token, id, input).await },
        )
        .await
    }

    /// Deletes an audit for an authenticated session.
    pub async fn delete_audit(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "audits.delete",
            session_token,
            "delete",
            "audit",
            Some(id),
            |session| async move { self.tasks.delete_audit(&session.token, id).await },
        )
        .await
    }

    /// Fetches an audit for an authenticated session.
    pub async fn get_audit(&self, session_token: &str, id: &str) -> Result<Task, GatewayError> {
        self.execute_with_resource(
            "audits.get",
            session_token,
            "read",
            "audit",
            Some(id),
            |session| async move { self.tasks.get_audit(&session.token, id).await },
        )
        .await
    }

    /// Starts an audit for an authenticated session.
    pub async fn start_audit(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<TaskAction, GatewayError> {
        self.execute_with_resource(
            "audits.start",
            session_token,
            "start",
            "audit",
            Some(id),
            |session| async move { self.tasks.start_audit(&session.token, id).await },
        )
        .await
    }

    /// Stops a running audit for an authenticated session.
    pub async fn stop_audit(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "audits.stop",
            session_token,
            "stop",
            "audit",
            Some(id),
            |session| async move { self.tasks.stop_audit(&session.token, id).await },
        )
        .await
    }

    /// Resumes a stopped audit for an authenticated session.
    pub async fn resume_audit(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<TaskAction, GatewayError> {
        self.execute_with_resource(
            "audits.resume",
            session_token,
            "resume",
            "audit",
            Some(id),
            |session| async move { self.tasks.resume_audit(&session.token, id).await },
        )
        .await
    }
}
